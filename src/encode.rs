use crate::types::BlockSize;
use crate::types::BlockStorageError;
use crate::types::ReadCapability;
use std::io::Read;

use chacha20::cipher::NewCipher;
use chacha20::cipher::StreamCipher;
use chacha20::{ChaCha20, Key as ChaChaKey, Nonce};

use crate::arity;
use crate::blake2b256_hash;
use crate::constants::{KEY_SIZE_BYTES, REF_SIZE_BYTES};
use crate::types::{
    BlockWithReference, BlockWithReferenceWriteFn, Key, Reference, ReferenceKeyPair,
};

struct EncryptBlockReturn {
    encrypted_block: Vec<u8>,
    reference: Reference,
    key: Key,
}

fn encrypt_node(input: &[u8], level: u8, convergence_secret: Option<&[u8]>) -> EncryptBlockReturn {
    let key_slice = blake2b256_hash(input, convergence_secret);
    let key = ChaChaKey::from_slice(&key_slice);
    let nonce_slice = &[level, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let nonce = Nonce::from_slice(nonce_slice);

    let mut encrypted_block = Vec::from(input);
    let mut cipher = ChaCha20::new(key, nonce);
    cipher.apply_keystream(&mut encrypted_block);
    let reference = blake2b256_hash(&encrypted_block, None);

    EncryptBlockReturn {
        encrypted_block,
        reference,
        key: key_slice,
    }
}

fn encrypt_internal_node(input: &[u8], level: u8) -> EncryptBlockReturn {
    encrypt_node(input, level, None)
}

fn encrypt_leaf_node(input: &[u8], convergence_secret: &[u8]) -> EncryptBlockReturn {
    encrypt_node(input, 0, Some(convergence_secret))
}

struct SplitContentReturn {
    rk_pairs: Vec<ReferenceKeyPair>,
}

fn pad(input: &mut Vec<u8>, start_index: usize) -> Option<Vec<u8>> {
    if input.len() - start_index == 0 {
        let mut vec = Vec::with_capacity(input.len());
        vec.fill(0);
        vec[0] = 0x80;
        Some(vec)
    } else {
        input[start_index] = 0x80;
        for i in input.iter_mut().skip(start_index + 1) {
            *i = 0x00;
        }
        None
    }
}

fn split_content(
    content: &mut dyn std::io::Read,
    convergence_secret: &[u8],
    block_size_bytes: usize,
    block_write_fn: &BlockWithReferenceWriteFn,
) -> Result<SplitContentReturn, BlockStorageError> {
    let mut rk_pairs: Vec<ReferenceKeyPair> = Vec::new();
    // we might produce an additional block due to padding
    let mut last_buffer: Vec<u8> = Vec::new();

    loop {
        let mut bytes_read = 0;
        let mut last_block = false;
        let mut blocks_to_write: Vec<&Vec<u8>> = Vec::new();
        let mut buffer: Vec<u8> = vec![0; block_size_bytes];

        while bytes_read < block_size_bytes {
            let n = match content.read(&mut buffer[bytes_read..]) {
                Ok(v) => v,
                Err(e) => return Err(e),
            };
            if n == 0 {
                last_block = true;
                break;
            }
            bytes_read += n;
        }
        if last_block {
            if let Some(last_block) = pad(&mut buffer, bytes_read) {
                last_buffer.copy_from_slice(&last_block);
                blocks_to_write.push(&last_buffer);
            }
        }
        blocks_to_write.push(&buffer);
        for block in blocks_to_write {
            let EncryptBlockReturn {
                encrypted_block,
                reference,
                key,
            } = encrypt_leaf_node(block, convergence_secret);
            {
                let rk_pair = ReferenceKeyPair { reference, key };
                match block_write_fn(BlockWithReference {
                    block: encrypted_block,
                    reference: rk_pair.reference,
                }) {
                    Ok(_) => rk_pairs.push(rk_pair),
                    Err(e) => return Err(e),
                }
            }
        }
        if last_block {
            break;
        }
    }
    Ok(SplitContentReturn { rk_pairs })
}

struct RKPairPacker {
    pairs: Vec<ReferenceKeyPair>,
    arity: usize,
    cycle: usize,
}

impl RKPairPacker {
    fn new(pairs: Vec<ReferenceKeyPair>, arity: usize) -> RKPairPacker {
        RKPairPacker {
            pairs,
            arity,
            cycle: 0,
        }
    }
}

impl Iterator for RKPairPacker {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Vec<u8>> {
        let mut result: Vec<u8> = Vec::new();
        let cycles_needed = match self.pairs.len() % self.arity {
            0 => self.pairs.len() / self.arity,
            _ => self.pairs.len() / self.arity + 1,
        };
        if self.cycle == cycles_needed {
            return None;
        }
        for count in 0..self.arity {
            match self.pairs.get(self.cycle * self.arity + count) {
                Some(pair) => {
                    let mut refkey = [pair.reference, pair.key].concat();
                    result.append(&mut refkey)
                }
                None => {
                    let mut empty_block: Vec<u8> = vec![0; REF_SIZE_BYTES + KEY_SIZE_BYTES];
                    result.append(&mut empty_block)
                }
            }
        }
        self.cycle += 1;
        Some(result)
    }
}

fn collect_rk_pairs(
    input_pairs: Vec<ReferenceKeyPair>,
    level: u8,
    block_size_bytes: usize,
    block_write_fn: &BlockWithReferenceWriteFn,
) -> Result<Vec<ReferenceKeyPair>, BlockStorageError> {
    let mut output_rk_pairs: Vec<ReferenceKeyPair> = Vec::new();
    for node in RKPairPacker::new(input_pairs, arity(block_size_bytes)) {
        let EncryptBlockReturn {
            encrypted_block,
            reference,
            key,
        } = encrypt_internal_node(&node, level);
        {
            let rk_pair = ReferenceKeyPair { reference, key };
            match block_write_fn(BlockWithReference {
                block: encrypted_block,
                reference: rk_pair.reference,
            }) {
                Ok(_) => output_rk_pairs.push(rk_pair),
                Err(e) => return Err(e),
            }
        }
    }
    Ok(output_rk_pairs)
}

pub fn encode(
    content: &mut dyn Read,
    convergence_secret: &[u8],
    block_size: BlockSize,
    block_write_fn: &BlockWithReferenceWriteFn,
) -> Result<ReadCapability, BlockStorageError> {
    let mut level = 0;

    let block_size_bytes = match block_size {
        BlockSize::Size1KiB => 1024,
        BlockSize::Size32KiB => 32 * 1024,
    };

    match split_content(
        content,
        convergence_secret,
        block_size_bytes,
        block_write_fn,
    ) {
        Ok(SplitContentReturn { rk_pairs }) => {
            let mut rk_pairs: Vec<ReferenceKeyPair> = rk_pairs;
            while rk_pairs.len() > 1 {
                level += 1;
                match collect_rk_pairs(rk_pairs, level, block_size_bytes, block_write_fn) {
                    Ok(pairs) => rk_pairs = pairs,
                    Err(e) => return Err(e),
                }
            }
            Ok(ReadCapability {
                level,
                root: rk_pairs[0],
                block_size,
            })
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::REFKEY_SIZE_BYTES;
    use crate::tests::vectors::read_positive_test_vectors;
    use crate::types::BlockStorageError;
    use hex_literal::hex;
    use std::collections::HashMap;
    use std::io::Cursor;
    use std::sync::mpsc;
    use std::sync::mpsc::{Receiver, Sender};
    use std::{thread, vec};

    #[test]
    fn test_encrypt() {
        let test_data = hex!("5dc2de4e32d5a8855d24fb452a83a035c73bd295b766cd4b9a07060917ebe38b");
        let convergence_secret =
            hex!("d8ae7bfb1dd49edbe5fdefbf1eebe911a22e06d66a1091519e61a8650ca7a8a1");
        let result = encrypt_leaf_node(&test_data, &convergence_secret);
        assert_ne!(result.encrypted_block, test_data);
    }

    // Streams a certain amount of bytes
    struct ChaCha20ZeroReader {
        read_total: usize,
        max: usize,
        cipher: ChaCha20,
        count: u64,
    }

    impl ChaCha20ZeroReader {
        fn new(max: usize, key: &[u8; REFKEY_SIZE_BYTES]) -> ChaCha20ZeroReader {
            let nonce = Nonce::from_slice(&[0; 12]);
            let chacha_key = ChaChaKey::from_slice(key);
            ChaCha20ZeroReader {
                max,
                read_total: 0,
                cipher: ChaCha20::new(chacha_key, nonce),
                count: 0,
            }
        }
    }

    impl Read for ChaCha20ZeroReader {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
            let to_read = (self.max - self.read_total).clamp(0, buf.len());
            self.cipher.apply_keystream(&mut buf[0..to_read]);
            self.read_total += to_read;
            self.count += 1;
            Ok(to_read)
        }
    }

    #[test]
    fn test_hello_world() {
        let payload = "Hello world!";
        let block_size = BlockSize::Size1KiB;
        let convergence_secret: [u8; 32] = Default::default();
        let write_fn =
            move |block_with_reference: BlockWithReference| -> Result<usize, BlockStorageError> {
                let size = block_with_reference.block.len();
                Ok(size)
            };

        let read_capability = encode(
            &mut payload.as_bytes(),
            &convergence_secret,
            block_size,
            &write_fn,
        )
        .unwrap();
        let encoded_urn = read_capability.to_urn();
        assert_eq!(encoded_urn, "urn:eris:BIAD77QDJMFAKZYH2DXBUZYAP3MXZ3DJZVFYQ5DFWC6T65WSFCU5S2IT4YZGJ7AC4SYQMP2DM2ANS2ZTCP3DJJIRV733CRAAHOSWIYZM3M");
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_chacha20_reader_100MiB() {
        let name = "chachacha";
        let key = blake2b256_hash(name.as_bytes(), None);
        let size = 100 * 1024 * 1024;
        let mut reader = ChaCha20ZeroReader::new(size, &key);
        let mut read_total = 0;
        let mut first_block = Vec::new();
        let mut last_block = Vec::new();

        loop {
            let mut buf = [0; 1024];
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(s) => {
                    if first_block.is_empty() {
                        first_block.extend_from_slice(&buf[..s])
                    }
                    last_block.extend_from_slice(&buf[..s]);
                    read_total += s;
                }
                Err(_) => {
                    panic!("unexpected error")
                }
            }
        }
        assert_eq!(read_total, size);
        let exp_first_ten_b32 = "OQTYRF453ZMTSPSY";
        let exp_last_ten_b32 = "6SEHZ3OIUBEYPXMT";

        let base32_alphabet = base32::Alphabet::RFC4648 { padding: false };
        let first_ten_b32 = base32::encode(base32_alphabet, &first_block[0..10]);
        let last_ten_b32 = base32::encode(base32_alphabet, &last_block[last_block.len() - 10..]);
        assert_eq!(exp_first_ten_b32, first_ten_b32);
        assert_eq!(exp_last_ten_b32, last_ten_b32);
    }

    #[test]
    fn test_large_payloads() {
        struct LargePayload {
            name: String,
            size: usize,
            urn: String,
            block_size: BlockSize,
        }

        let payloads: Vec<LargePayload> = vec![
            LargePayload{
                name: "100MiB (block size 1KiB)".to_owned(),
                size: 100*1024*1024, // 100MiB
                urn: "urn:eris:BIC6F5EKY2PMXS2VNOKPD3AJGKTQBD3EXSCSLZIENXAXBM7PCTH2TCMF5OKJWAN36N4DFO6JPFZBR3MS7ECOGDYDERIJJ4N5KAQSZS67YY".to_owned(),
                block_size: BlockSize::Size1KiB
            },
            LargePayload{
                name: "1GiB (block size 32KiB)".to_owned(),
                size: 1024*1024*1024, // 1GiB
                urn: "urn:eris:B4BL4DKSEOPGMYS2CU2OFNYCH4BGQT774GXKGURLFO5FDXAQQPJGJ35AZR3PEK6CVCV74FVTAXHRSWLUUNYYA46ZPOPDOV2M5NVLBETWVI".to_owned(),
                block_size: BlockSize::Size32KiB
            },
            // Takes a long time to complete
            LargePayload{
                name: "256GiB (block size 32KiB)".to_owned(),
                size: 256*1024*1024*1024, // 1GiB
                urn: "urn:eris:B4B5DNZVGU4QDCN7TAYWQZE5IJ6ESAOESEVYB5PPWFWHE252OY4X5XXJMNL4JMMFMO5LNITC7OGCLU4IOSZ7G6SA5F2VTZG2GZ5UCYFD5E".to_owned(),
                block_size: BlockSize::Size32KiB
            }
        ];

        for payload in payloads {
            let key = blake2b256_hash(payload.name.as_bytes(), None);

            let cha_cha_reader = ChaCha20ZeroReader::new(payload.size, &key);
            let mut reader = cha_cha_reader;

            let write_fn = move |block_with_reference: BlockWithReference| -> Result<usize, BlockStorageError> {
                let size = block_with_reference.block.len();
                Ok(size)
            };
            let convergence_secret: [u8; 32] = Default::default();
            let res = encode(
                &mut reader,
                &convergence_secret,
                payload.block_size,
                &write_fn,
            )
            .unwrap();
            let encoded_urn = res.to_urn();
            assert_eq!(payload.urn, encoded_urn);
        }
    }

    #[test]
    fn test_hello_world_cha_cha() {
        let name = "Hello World!";
        let key = blake2b256_hash(name.as_bytes(), None);
        let size = 1024; // 1 kb
        let urn = "urn:eris:BIAVWP2IZZ2A3WNGPMDSGFE2FJUHFYSEOKKM76DOA2J2XYLOUBSINJEVFKDT2VKH4BVNQPGZVZZTFSK5JFUZ3FTKXVX6TYCZY762UYZYG4";
        let block_size = BlockSize::Size1KiB;

        let mut reader = ChaCha20ZeroReader::new(size, &key);
        let write_fn =
            move |block_with_reference: BlockWithReference| -> Result<usize, BlockStorageError> {
                let size = block_with_reference.block.len();
                Ok(size)
            };
        let convergence_secret: [u8; 32] = Default::default();
        let res = encode(&mut reader, &convergence_secret, block_size, &write_fn).unwrap();
        let encoded_urn = res.to_urn();
        assert_eq!(urn, encoded_urn);
    }

    // Tests whether encode() is reading into a zero'ed buffer,
    // not doing that will XOR old data and thus produce a different
    // cipher stream
    #[test]
    fn test_chacha_reader() {
        let name = "ChaCha!";
        let key = blake2b256_hash(name.as_bytes(), None);
        let size = 10 * 1024; // 10 kb
        let block_size = BlockSize::Size1KiB;

        let mut reader = ChaCha20ZeroReader::new(size, &key);
        let write_fn =
            move |block_with_reference: BlockWithReference| -> Result<usize, BlockStorageError> {
                let size = block_with_reference.block.len();
                Ok(size)
            };
        let convergence_secret: [u8; 32] = Default::default();
        let res_direct = encode(&mut reader, &convergence_secret, block_size, &write_fn).unwrap();
        let urn_direct = res_direct.to_urn();

        let mut chacha2 = ChaCha20ZeroReader::new(size, &key);
        let mut cha_cha_content = Vec::<u8>::new();
        loop {
            let mut buf = [0; 1024];
            match chacha2.read(&mut buf) {
                Ok(0) => break,
                Ok(s) => {
                    cha_cha_content.extend_from_slice(&buf[..s]);
                }
                Err(_) => {
                    panic!("unexpected error")
                }
            }
        }
        let mut reader2 = Cursor::new(cha_cha_content);
        let res_indirect =
            encode(&mut reader2, &convergence_secret, block_size, &write_fn).unwrap();
        let urn_indirect = res_indirect.to_urn();
        assert_eq!(urn_direct, urn_indirect);
    }

    #[test]
    fn test_encode() {
        let test_vectors = read_positive_test_vectors();
        for vector in test_vectors {
            println!("Running vector {}", vector.file_name);

            let base32_alphabet = base32::Alphabet::RFC4648 { padding: false };
            let content = base32::decode(base32_alphabet, &vector.data.content).unwrap();

            let mut cursor = Cursor::new(content);
            let convergence_secret =
                base32::decode(base32_alphabet, &vector.data.convergence_secret).unwrap();

            let block_size = match vector.data.block_size {
                1024 => BlockSize::Size1KiB,
                32768 => BlockSize::Size32KiB,
                _ => panic!("unsupported blocksize encountered"),
            };

            let mut generated_blocks: HashMap<String, Vec<u8>> = HashMap::new();

            let (block_tx, block_rx): (Sender<BlockWithReference>, Receiver<BlockWithReference>) =
                mpsc::channel();
            let (return_tx, return_rx): (Sender<ReadCapability>, Receiver<ReadCapability>) =
                mpsc::channel();

            let write_fn = move |block_with_reference: BlockWithReference| -> Result<usize, BlockStorageError> {
                let size = block_with_reference.block.len();
                block_tx.send(block_with_reference).unwrap();
                Ok(size)
            };

            let encoder = thread::spawn(move || {
                let res = encode(&mut cursor, &convergence_secret, block_size, &write_fn);
                return_tx.send(res.unwrap()).unwrap();
            });

            while let Ok(block_with_reference) = block_rx.recv() {
                let b32_ref = base32::encode(base32_alphabet, &block_with_reference.reference);
                generated_blocks.insert(b32_ref, block_with_reference.block);
            }
            let result = return_rx.recv().unwrap();
            encoder.join().unwrap();

            let b32_root_key = base32::encode(base32_alphabet, &result.root.key);
            let b32_root_ref = base32::encode(base32_alphabet, &result.root.reference);
            assert_eq!(vector.data.blocks.len(), generated_blocks.len());
            assert_eq!(vector.data.read_capability.level, result.level);
            assert_eq!(vector.data.read_capability.root_reference, b32_root_ref);
            assert_eq!(vector.data.read_capability.root_key, b32_root_key);

            for block in &generated_blocks {
                let bs_usize: usize = block_size.into();
                assert_eq!(block.1.len(), bs_usize);
            }
            for (_, block) in generated_blocks.iter().enumerate() {
                let reference = blake2b256_hash(block.1, None);
                let b32_reference = base32::encode(base32_alphabet, &reference);
                assert!(vector.data.blocks.contains_key(&b32_reference));
            }
        }
    }
}
