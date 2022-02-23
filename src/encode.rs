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

fn encrypt_block(input: &[u8], convergence_secret: &[u8]) -> EncryptBlockReturn {
    let key_slice = &blake2b256_hash(input, Some(convergence_secret));
    let key = ChaChaKey::from_slice(key_slice);

    let mut encrypted_block = Vec::from(input);

    let nonce = Nonce::from_slice(&[0; 12]); // 96-bit is set to zero, section 2.1.2
    let mut cipher = ChaCha20::new(key, nonce);
    cipher.apply_keystream(&mut encrypted_block);

    let reference = blake2b256_hash(&encrypted_block, None);

    return EncryptBlockReturn {
        encrypted_block: encrypted_block,
        reference: reference,
        key: *key_slice,
    };
}

struct SplitContentReturn {
    rk_pairs: Vec<ReferenceKeyPair>,
}

fn pad(input: &mut Vec<u8>, start_index: usize) -> Option<Vec<u8>> {
    if input.len() - start_index == 0 {
        let mut vec = Vec::with_capacity(input.len());
        vec.fill(0);
        vec[0] = 0x80;
        return Some(vec);
    } else {
        input[start_index] = 0x80;
        for i in start_index + 1..input.len() {
            input[i] = 0x00;
        }
        return None;
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
        let mut buffer: Vec<u8> = Vec::with_capacity(block_size_bytes);
        buffer.resize(block_size_bytes, 0);

        while bytes_read < block_size_bytes {
            let n = match content.read(&mut buffer[bytes_read..]) {
                Ok(v) => v,
                Err(e) => return Err(e)
            };
            if n == 0 {
                last_block = true;
                break;
            }
            bytes_read += n;
        }
        if last_block {
            match pad(&mut buffer, bytes_read) {
                Some(last_block) => {
                    last_buffer.copy_from_slice(&last_block);
                    blocks_to_write.push(&last_buffer);
                }
                None => {}
            }
        }
        blocks_to_write.push(&buffer);
        for block in blocks_to_write {
            match encrypt_block(block, convergence_secret) {
                EncryptBlockReturn {
                    encrypted_block,
                    reference,
                    key,
                } => {
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
        }
        if last_block {
            break;
        }
    }
    Ok(SplitContentReturn { rk_pairs: rk_pairs })
}

struct RKPairPacker {
    pairs: Vec<ReferenceKeyPair>,
    arity: usize,
    cycle: usize,
}

impl RKPairPacker {
    fn new(pairs: Vec<ReferenceKeyPair>, arity: usize) -> RKPairPacker {
        RKPairPacker {
            pairs: pairs,
            arity: arity,
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
        return Some(result);
    }
}

fn collect_rk_pairs(
    input_pairs: Vec<ReferenceKeyPair>,
    convergence_secret: &[u8],
    block_size_bytes: usize,
    block_write_fn: &BlockWithReferenceWriteFn,
) -> Result<Vec<ReferenceKeyPair>, BlockStorageError> {
    let mut output_rk_pairs: Vec<ReferenceKeyPair> = Vec::new();
    for node in RKPairPacker::new(input_pairs, arity(block_size_bytes)) {
        match encrypt_block(&node, convergence_secret) {
            EncryptBlockReturn {
                encrypted_block,
                reference,
                key,
            } => {
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
    }
    return Ok(output_rk_pairs);
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
            let mut rk_pairs: Vec<ReferenceKeyPair> = Vec::from(rk_pairs);
            while rk_pairs.len() > 1 {
                match collect_rk_pairs(
                    rk_pairs,
                    convergence_secret,
                    block_size_bytes,
                    block_write_fn,
                ) {
                    Ok(pairs) => rk_pairs = pairs,
                    Err(e) => return Err(e),
                }
                level += 1;
            }
            return Ok(ReadCapability {
                level: level,
                root: rk_pairs[0],
                block_size: block_size,
            });
        }
        Err(e) => return Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::REFKEY_SIZE_BYTES;
    use crate::types::BlockStorageError;
    use hex_literal::hex;
    use std::cmp::{max, min};
    use std::collections::HashMap;
    use std::io::Cursor;
    use std::sync::mpsc;
    use std::sync::mpsc::{Receiver, Sender};
    use std::thread;
    use crate::tests::vectors::read_test_vectors;

    #[test]
    fn test_encrypt() {
        let test_data = hex!("5dc2de4e32d5a8855d24fb452a83a035c73bd295b766cd4b9a07060917ebe38b");
        let convergence_secret =
            hex!("d8ae7bfb1dd49edbe5fdefbf1eebe911a22e06d66a1091519e61a8650ca7a8a1");
        let result = encrypt_block(&test_data, &convergence_secret);
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
                max: max,
                read_total: 0,
                cipher: ChaCha20::new(chacha_key, nonce),
                count: 0,
            }
        }
    }

    impl Read for ChaCha20ZeroReader {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
            let to_read = min(max(self.max - self.read_total, 0), buf.len());
            self.cipher.apply_keystream(&mut buf[0..to_read]);
            self.read_total += to_read;
            self.count+=1;
            return Ok(to_read);
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_chacha20_reader_100MiB() {
        let name = "chachacha";
        let key = blake2b256_hash(name.as_bytes(), None);
        let size = 100*1024*1024;
        let mut reader = ChaCha20ZeroReader::new(size, &key);
        let mut read_total = 0;
        let mut first_block = Vec::new();
        let mut last_block = Vec::new();

        loop {
            let mut buf = [0; 1024];
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(s) => {
                    if first_block.len() == 0 {
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
        let exp_last_ten_b32  = "6SEHZ3OIUBEYPXMT";

        let base32_alphabet = base32::Alphabet::RFC4648 { padding: false };
        let first_ten_b32 = base32::encode(base32_alphabet, &first_block[0..10]);
        let last_ten_b32 = base32::encode(base32_alphabet, &last_block[last_block.len()-10..]);
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
                urn: "urn:erisx2:BICXPZNDNXFLO4IOMF6VIV2ZETGUJEUU7GN4AHPWNKEN6KJMCNP6YNUMVW2SCGZUJ4L3FHIXVECRZQ3QSBOTYPGXHN2WRBMB27NXDTAP24".to_owned(),
                block_size: BlockSize::Size1KiB
            },
            LargePayload{
                name: "1GiB (block size 32KiB)".to_owned(),
                size: 1024*1024*1024, // 1GiB
                urn: "urn:erisx2:B4BFG37LU5BM5N3LXNPNMGAOQPZ5QTJAV22XEMX3EMSAMTP7EWOSD2I7AGEEQCTEKDQX7WCKGM6KQ5ALY5XJC4LMOYQPB2ZAFTBNDB6FAA".to_owned(),
                block_size: BlockSize::Size32KiB
            },
            // Takes a long time to complete
            //LargePayload{
            //    name: "256GiB (block size 32KiB)".to_owned(),
            //    size: 256*1024*1024*1024, // 1GiB
            //    urn: "urn:erisx2:B4BZHI55XJYINGLXWKJKZHBIXN6RSNDU233CY3ELFSTQNSVITBSVXGVGBKBCS4P4M5VSAUOZSMVAEC2VDFQTI5SEYVX4DN53FTJENWX4KU".to_owned(),
            //    block_size: BlockSize::Size32KiB
            //}
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
            let res = encode(&mut reader, &convergence_secret, payload.block_size, &write_fn).unwrap();
            let encoded_urn = res.to_urn();
            assert_eq!(payload.urn, encoded_urn);
        }
    }

    #[test]
    fn test_hello_world_cha_cha() {
        let name = "Hello World!";
        let key = blake2b256_hash(name.as_bytes(), None);
        let size = 1024; // 1 kb
        let urn = "urn:erisx2:BIASC77CCCHLMNC2TFDQMCZ2747ZQGIJJPRFMCDQC7K3LBITVOVDHA3EDSZD3HSDLOOLBO5LYWTAWCEZ2O4X65KXB6Y3TESHVVVIVOEEYM";
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
        let size = 10*1024; // 10 kb
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
        let res_indirect = encode(&mut reader2, &convergence_secret, block_size, &write_fn).unwrap();
        let urn_indirect = res_indirect.to_urn();
        assert_eq!(urn_direct, urn_indirect);
    }

    #[test]
    fn test_encode() {
        let test_vectors = read_test_vectors();
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

            loop {
                match block_rx.recv() {
                    Ok(block_with_reference) => {
                        let b32_ref =
                            base32::encode(base32_alphabet, &block_with_reference.reference);
                        generated_blocks.insert(b32_ref, block_with_reference.block);
                    }
                    Err(_) => break,
                }
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
                assert_eq!(block.1.len(), vector.data.block_size);
            }
            for (_, block) in generated_blocks.iter().enumerate() {
                let reference = blake2b256_hash(&block.1, None);
                let b32_reference = base32::encode(base32_alphabet, &reference);
                assert_eq!(vector.data.blocks.contains_key(&b32_reference), true);
            }
        }
    }
}
