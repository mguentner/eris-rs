use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::{ChaCha20, Key as ChaChaKey, Nonce};
use std::io::Write;

use crate::arity;
use crate::blake2b256_hash;
use crate::constants::{KEY_SIZE_BYTES, REF_SIZE_BYTES};
use crate::types::NodeParsingError;
use crate::types::NodeParsingErrorKind;
use crate::types::{
    BlockStorageError, BlockStorageErrorKind, BlockStorageGetFn, ReadCapability, ReferenceKeyPair,
};

pub fn decrypt_block(block: &[u8], level: u8, key: &[u8]) -> Vec<u8> {
    let mut vec = Vec::from(block);
    let key = ChaChaKey::from_slice(key);
    let nonce_slice = &[level, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let nonce = Nonce::from_slice(nonce_slice);
    let mut cipher = ChaCha20::new(key, nonce);
    cipher.apply_keystream(&mut vec);
    vec
}

struct RKPairUnpacker {
    block: Vec<u8>,
    count: usize,
}

impl RKPairUnpacker {
    fn new(block: Vec<u8>) -> RKPairUnpacker {
        RKPairUnpacker { block, count: 0 }
    }
}

impl Iterator for RKPairUnpacker {
    type Item = Result<ReferenceKeyPair, NodeParsingError>;

    fn next(&mut self) -> Option<Result<ReferenceKeyPair, NodeParsingError>> {
        let arity = arity(self.block.len());
        if self.count >= arity {
            return None;
        }
        let offset = self.count * (REF_SIZE_BYTES + KEY_SIZE_BYTES);
        let mut reference: [u8; REF_SIZE_BYTES] = Default::default();
        let mut key: [u8; KEY_SIZE_BYTES] = Default::default();
        reference.clone_from_slice(&self.block[offset..offset + REF_SIZE_BYTES]);
        key.clone_from_slice(
            &self.block[offset + REF_SIZE_BYTES..offset + REF_SIZE_BYTES + KEY_SIZE_BYTES],
        );
        self.count += 1;
        match reference.iter().filter(|x| **x != 0).count() {
            // reference contains only zeros, we have reached the padding area
            0 => {
                // check whether everything left of the reference is also zeroed
                match self.block[offset + REF_SIZE_BYTES..]
                    .iter()
                    .filter(|x| **x != 0)
                    .count()
                {
                    0 => None,
                    _ => Some(Err(NodeParsingError::new(
                        NodeParsingErrorKind::InvalidData,
                        "Found data after padding area.",
                    ))),
                }
            }
            _ => Some(Ok(ReferenceKeyPair { reference, key })),
        }
    }
}

fn decode_recurse_all_rk_pairs(
    level: u8,
    block_size_bytes: usize,
    node: ReferenceKeyPair,
    block_storage_get: &BlockStorageGetFn,
) -> Result<Vec<ReferenceKeyPair>, BlockStorageError> {
    let mut result: Vec<ReferenceKeyPair> = Vec::new();
    if level == 0 {
        result.push(node);
    } else {
        match block_storage_get(node.reference) {
            Ok(encrypted_node) => {
                if block_size_bytes != encrypted_node.len() {
                    return Err(BlockStorageError::new(
                        BlockStorageErrorKind::Other,
                        "unexpected block_size_bytes",
                    ));
                }
                let encrypted_block_hashed = blake2b256_hash(&encrypted_node, None);
                if node.reference != encrypted_block_hashed {
                    return Err(BlockStorageError::new(
                        BlockStorageErrorKind::InvalidData,
                        "Block is corrupted",
                    ));
                }
                let decrypted_block = decrypt_block(&encrypted_node, level, &node.key);
                for sub_node_result in RKPairUnpacker::new(decrypted_block) {
                    match sub_node_result {
                        Ok(sub_node) => match decode_recurse_all_rk_pairs(
                            level - 1,
                            block_size_bytes,
                            sub_node,
                            block_storage_get,
                        ) {
                            Ok(v) => result.extend(v),
                            Err(e) => return Err(e),
                        },
                        Err(e) => return Err(e),
                    }
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(result)
}

fn unpad(input: &Vec<u8>) -> Result<&[u8], BlockStorageError> {
    for idx in 0..input.len() {
        let cursor = input.len() - 1 - idx;
        if input[cursor] == 0x80 {
            return Ok(&input[0..cursor]);
        }
        if !(input[cursor] == 0x80 || input[cursor] == 0x00) {
            return Err(BlockStorageError::new(
                BlockStorageErrorKind::InvalidData,
                "unexpected character encountered in input",
            ));
        }
    }
    Err(BlockStorageError::new(
        BlockStorageErrorKind::InvalidData,
        "no valid padding found",
    ))
}

pub fn decode(
    read_capability: ReadCapability,
    writer: &mut dyn Write,
    block_storage_get: &BlockStorageGetFn,
) -> Result<usize, BlockStorageError> {
    let mut level_0_rk_pairs: Vec<ReferenceKeyPair> = Vec::new();
    let level = read_capability.level;
    let block_size_bytes: usize = read_capability.block_size.into();
    let root = read_capability.root;
    if level == 0 {
        level_0_rk_pairs.push(root);
    } else {
        match decode_recurse_all_rk_pairs(level, block_size_bytes, root, block_storage_get) {
            Ok(v) => level_0_rk_pairs.append(&mut v.clone()),
            Err(e) => return Err(e),
        }
    }
    let mut bytes_written = 0;
    for (idx, rk_pair) in level_0_rk_pairs.iter().enumerate() {
        let is_last_block = idx == level_0_rk_pairs.len() - 1;
        match block_storage_get(rk_pair.reference) {
            Ok(encrypted_node) => {
                if block_size_bytes != encrypted_node.len() {
                    return Err(BlockStorageError::new(
                        BlockStorageErrorKind::Other,
                        "unexpected block_size_bytes",
                    ));
                }
                let encrypted_block_hashed = blake2b256_hash(&encrypted_node, None);
                if rk_pair.reference != encrypted_block_hashed {
                    return Err(BlockStorageError::new(
                        BlockStorageErrorKind::InvalidData,
                        "Block is corrupted",
                    ));
                }
                let decrypted_block = decrypt_block(&encrypted_node, 0, &rk_pair.key);
                let data = match is_last_block {
                    true => match unpad(&decrypted_block) {
                        Ok(unpadded) => unpadded,
                        Err(e) => return Err(e),
                    },
                    false => &decrypted_block,
                };
                match writer.write(data) {
                    Ok(n) => bytes_written += n,
                    Err(e) => return Err(e),
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(bytes_written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::REFKEY_SIZE_BYTES;
    use crate::tests::vectors::{read_negative_test_vectors, read_positive_test_vectors};
    use crate::types::{Reference, ReferenceKeyPair};
    use std::io::Cursor;

    #[test]
    fn test_decode_positive() {
        let test_vectors = read_positive_test_vectors();
        for vector in test_vectors {
            println!("Running vector {}", vector.file_name);
            let base32_alphabet = base32::Alphabet::RFC4648 { padding: false };
            let expected_content = base32::decode(base32_alphabet, &vector.data.content).unwrap();

            let mut root_key: [u8; REFKEY_SIZE_BYTES] = Default::default();
            root_key.clone_from_slice(
                &base32::decode(base32_alphabet, &vector.data.read_capability.root_key).unwrap(),
            );
            let mut root_ref: [u8; REFKEY_SIZE_BYTES] = Default::default();
            root_ref.clone_from_slice(
                &base32::decode(base32_alphabet, &vector.data.read_capability.root_reference)
                    .unwrap(),
            );
            let root_key_ref = ReferenceKeyPair {
                reference: root_ref,
                key: root_key,
            };

            let blocks = vector.data.blocks;

            let block_storage_get_fn =
                move |reference: Reference| -> Result<Vec<u8>, BlockStorageError> {
                    let b32_ref = base32::encode(base32_alphabet, &reference);
                    match blocks.get(&b32_ref) {
                        Some(block) => match base32::decode(base32_alphabet, block) {
                            Some(d) => Ok(d),
                            None => Err(BlockStorageError::new(
                                BlockStorageErrorKind::InvalidData,
                                "could not decode data",
                            )),
                        },
                        None => Err(BlockStorageError::new(
                            BlockStorageErrorKind::NotFound,
                            "could not retrieve block",
                        )),
                    }
                };

            let content: Vec<u8> = Vec::new();
            let mut cursor = Cursor::new(content);
            let read_capability = ReadCapability {
                level: vector.data.read_capability.level,
                block_size: vector.data.read_capability.block_size.try_into().unwrap(),
                root: root_key_ref,
            };
            match decode(read_capability, &mut cursor, &block_storage_get_fn) {
                Ok(res) => {
                    assert_eq!(expected_content.len(), cursor.get_ref().len());
                    assert_eq!(res, expected_content.len());
                    assert_eq!(
                        expected_content
                            .iter()
                            .zip(cursor.get_ref())
                            .filter(|&(a, b)| a != b)
                            .count(),
                        0
                    );
                }
                Err(e) => panic!("Expected the test to succeed. Got {e:?}"),
            }
        }
    }

    #[test]
    fn test_decode_negative() {
        let test_vectors = read_negative_test_vectors();
        for vector in test_vectors {
            println!("Running vector {}", vector.file_name);
            let base32_alphabet = base32::Alphabet::RFC4648 { padding: false };
            let mut root_key: [u8; REFKEY_SIZE_BYTES] = Default::default();
            root_key.clone_from_slice(
                &base32::decode(base32_alphabet, &vector.data.read_capability.root_key).unwrap(),
            );
            let mut root_ref: [u8; REFKEY_SIZE_BYTES] = Default::default();
            root_ref.clone_from_slice(
                &base32::decode(base32_alphabet, &vector.data.read_capability.root_reference)
                    .unwrap(),
            );
            let root_key_ref = ReferenceKeyPair {
                reference: root_ref,
                key: root_key,
            };

            let blocks = vector.data.blocks;

            let block_storage_get_fn =
                move |reference: Reference| -> Result<Vec<u8>, BlockStorageError> {
                    let b32_ref = base32::encode(base32_alphabet, &reference);
                    match blocks.get(&b32_ref) {
                        Some(block) => match base32::decode(base32_alphabet, block) {
                            Some(d) => Ok(d),
                            None => Err(BlockStorageError::new(
                                BlockStorageErrorKind::InvalidData,
                                "could not decode data",
                            )),
                        },
                        None => Err(BlockStorageError::new(
                            BlockStorageErrorKind::NotFound,
                            "could not retrieve block",
                        )),
                    }
                };
            let content: Vec<u8> = Vec::new();
            let mut cursor = Cursor::new(content);
            let read_capability = ReadCapability {
                level: vector.data.read_capability.level,
                block_size: vector.data.read_capability.block_size.try_into().unwrap(),
                root: root_key_ref,
            };
            match decode(read_capability, &mut cursor, &block_storage_get_fn) {
                Ok(_res) => {
                    panic!(
                        "Expected the test to fail with `{}`",
                        vector.data.description
                    )
                }
                Err(_e) => continue,
            }
        }
    }
}
