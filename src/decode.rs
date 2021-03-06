use std::io::Write;
use chacha20::cipher::NewCipher;
use chacha20::cipher::StreamCipher;
use chacha20::{ChaCha20, Key as ChaChaKey, Nonce};

use crate::arity;
use crate::types::{ReferenceKeyPair, BlockStorageError, BlockStorageGetFn, BlockStorageErrorKind, ReadCapability};
use crate::constants::{REF_SIZE_BYTES, KEY_SIZE_BYTES};

pub fn decrypt_block(block: &[u8], key: &[u8]) -> Vec<u8> {
    let mut vec = Vec::from(block);
    let key = ChaChaKey::from_slice(key);
    let nonce = Nonce::from_slice(&[0; 12]);
    let mut cipher = ChaCha20::new(key, nonce);
    cipher.apply_keystream(&mut vec);
    return vec;
}

struct RKPairUnpacker {
    block: Vec<u8>,
    count: usize
}

impl RKPairUnpacker {
    fn new(block: Vec<u8>) -> RKPairUnpacker {
        RKPairUnpacker {
            block: block,
            count: 0
        }
    }
}

impl Iterator for RKPairUnpacker {
    type Item = ReferenceKeyPair;

    fn next(&mut self) -> Option<ReferenceKeyPair> {
        let arity = arity(self.block.len());
        if self.count >= arity {
            return None;
        }
        let offset = self.count*(REF_SIZE_BYTES+KEY_SIZE_BYTES);
        let mut reference: [u8; REF_SIZE_BYTES] = Default::default();
        let mut key: [u8; KEY_SIZE_BYTES] = Default::default();
        reference.clone_from_slice(&self.block[offset..offset+REF_SIZE_BYTES]);
        key.clone_from_slice(&self.block[offset+REF_SIZE_BYTES..offset+REF_SIZE_BYTES+KEY_SIZE_BYTES]);
        self.count += 1;
        match reference.iter().filter(|x| **x != 0).count() {
            // reference contains only zeros, we have reached the padding area
            0 => return None,
            _ => return Some(ReferenceKeyPair{
                reference: reference,
                key: key,
            })
        }
    }
}


fn decode_recurse_all_rk_pairs(level: u8, block_size_bytes: usize, node: ReferenceKeyPair, block_storage_get: &BlockStorageGetFn) -> Result<Vec<ReferenceKeyPair>, BlockStorageError> {
    let mut result: Vec<ReferenceKeyPair> = Vec::new();
    if level == 0 {
        result.push(node);
    } else {
        match block_storage_get(node.reference) {
            Ok(encrypted_node) => {
                if block_size_bytes != encrypted_node.len() {
                    return Err(BlockStorageError::new(BlockStorageErrorKind::Other, "unexpected block_size_bytes"))
                }
                let decrypted_block = decrypt_block(&encrypted_node, &node.key);
                for sub_node in RKPairUnpacker::new(decrypted_block) {
                    match decode_recurse_all_rk_pairs(level-1, block_size_bytes, sub_node, block_storage_get) {
                        Ok(v) => result.extend(v),
                        Err(e) => return Err(e)
                    }
                }
            },
            Err(e) => {
                return Err(e)
            }
        }
    }
    return Ok(result);
}

fn unpad(input: &Vec<u8>) -> Result<&[u8], BlockStorageError> {
    for idx in 0..input.len() {
        let cursor = input.len()-1-idx;
        if input[cursor] == 0x80 {
            return Ok(&input[0..cursor]);
        }
        if !(input[cursor] == 0x80 || input[cursor] == 0x00) {
            return Err(BlockStorageError::new(BlockStorageErrorKind::InvalidData, "unexpected character encountered in input"));
        }
    }
    return Err(BlockStorageError::new(BlockStorageErrorKind::InvalidData, "no valid padding found"));
}

pub fn decode(read_capability: ReadCapability, writer: &mut dyn Write, block_storage_get: &BlockStorageGetFn) -> Result<usize, BlockStorageError> {
    let mut level_0_rk_pairs: Vec<ReferenceKeyPair> = Vec::new();
    let level = read_capability.level;
    let block_size_bytes: usize = read_capability.block_size.into();
    let root = read_capability.root;
    if level == 0 {
        level_0_rk_pairs.push(root);
    } else {
        match decode_recurse_all_rk_pairs(level, block_size_bytes, root, block_storage_get) {
            Ok(v) => level_0_rk_pairs.append(&mut v.clone()),
            Err(e) => return Err(e)
        }
    }
    let mut bytes_written = 0;
    for (idx, rk_pair) in level_0_rk_pairs.iter().enumerate() {
        let is_last_block = idx == level_0_rk_pairs.len()-1;
        match block_storage_get(rk_pair.reference) {
            Ok(encrypted_node) => {
                if block_size_bytes != encrypted_node.len() {
                    return Err(BlockStorageError::new(BlockStorageErrorKind::Other, "unexpected block_size_bytes"))
                }
                let decrypted_block = decrypt_block(&encrypted_node, &rk_pair.key);
                let data = match is_last_block {
                    true => match unpad(&decrypted_block) {
                        Ok(unpadded) => unpadded,
                        Err(e) => return Err(e)
                    },
                    false => &decrypted_block
                };
                match writer.write(data) {
                    Ok(n) => bytes_written += n,
                    Err(e) => return Err(e)
                }
            },
            Err(e) => {
                return Err(e)
            }
        }
    }
    return Ok(bytes_written);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::vectors::read_test_vectors;
    use std::io::Cursor;
    use crate::types::{ReferenceKeyPair, Reference};
    use crate::constants::{REFKEY_SIZE_BYTES};

    #[test]
    fn test_decode() {
        let test_vectors = read_test_vectors();
        for vector in test_vectors {
            println!("Running vector {}", vector.file_name);
            let base32_alphabet = base32::Alphabet::RFC4648 { padding: false };
            let expected_content = base32::decode(base32_alphabet, &vector.data.content).unwrap();

            let mut root_key: [u8; REFKEY_SIZE_BYTES] = Default::default();
            root_key.clone_from_slice(&base32::decode(base32_alphabet, &vector.data.read_capability.root_key).unwrap());
            let mut root_ref: [u8; REFKEY_SIZE_BYTES] = Default::default();
            root_ref.clone_from_slice(&base32::decode(base32_alphabet, &vector.data.read_capability.root_reference).unwrap());
            let root_key_ref = ReferenceKeyPair{
                reference: root_ref,
                key: root_key
            };

            let blocks = vector.data.blocks;

            let block_storage_get_fn  = move |reference: Reference| -> Result<Vec<u8>, BlockStorageError> {
                let b32_ref = base32::encode(base32_alphabet, &reference);
                match blocks.get(&b32_ref) {
                    Some(block) => {
                        match base32::decode(base32_alphabet, &block) {
                            Some(d) => return Ok(d),
                            None => Err(BlockStorageError::new(BlockStorageErrorKind::InvalidData, "could not decode data"))
                        }
                    },
                    None => return Err(BlockStorageError::new(BlockStorageErrorKind::NotFound, "could not retrieve block"))
                }
            };

            let content: Vec<u8> = Vec::new();
            let mut cursor = Cursor::new(content);
            let read_capability = ReadCapability{
                level: vector.data.read_capability.level,
                block_size: vector.data.read_capability.block_size.try_into().unwrap(),
                root: root_key_ref,
            };
            match decode(read_capability, &mut cursor, &block_storage_get_fn) {
                Ok(res) => {
                    assert_eq!(expected_content.len(), cursor.get_ref().len());
                    assert_eq!(res, expected_content.len());
                    assert_eq!(expected_content.iter().zip(cursor.get_ref()).filter(|&(a, b)| a != b).count(), 0);
                },
                Err(e) => panic!("Expected the test to succeed. Got {:?}", e)
            }
        }
    }
}
