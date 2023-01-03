use crate::constants::{KEY_SIZE_BYTES, REF_SIZE_BYTES};
use crate::types::{BlockSize, ReadCapability, ReferenceKeyPair};
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::convert::TryInto;

#[derive(Serialize, Deserialize, Debug)]
pub struct ReadCapabilityTest {
    #[serde(rename = "block-size")]
    pub block_size: usize,
    pub level: u8,
    #[serde(rename = "root-reference")]
    pub root_reference: String,
    #[serde(rename = "root-key")]
    pub root_key: String,
}

impl TryInto<ReadCapability> for ReadCapabilityTest {
    type Error = ();

    fn try_into(self) -> Result<ReadCapability, Self::Error> {
        let base32_alphabet = base32::Alphabet::RFC4648 { padding: false };
        match base32::decode(base32_alphabet, &self.root_key) {
            Some(root_key) => match base32::decode(base32_alphabet, &self.root_reference) {
                Some(root_reference) => {
                    let mut reference: [u8; REF_SIZE_BYTES] = Default::default();
                    let mut key: [u8; KEY_SIZE_BYTES] = Default::default();
                    key.copy_from_slice(&root_key);
                    reference.copy_from_slice(&root_reference);
                    let root = ReferenceKeyPair {
                        reference: reference,
                        key: key,
                    };
                    let block_size = match self.block_size {
                        1024 => BlockSize::Size1KiB,
                        32768 => BlockSize::Size32KiB,
                        _ => return Err(()),
                    };
                    Ok(ReadCapability {
                        level: self.level,
                        block_size: block_size,
                        root: root,
                    })
                }
                None => Err(()),
            },
            None => Err(()),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BaseTestVectorContent {
    #[serde(rename = "type")]
    pub test_type: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PositiveTestVectorContent {
    pub id: u32,
    #[serde(rename = "spec-version")]
    pub spec_version: String,
    pub name: String,
    pub description: String,
    pub content: String,
    #[serde(rename = "convergence-secret")]
    pub convergence_secret: String,
    #[serde(rename = "block-size")]
    pub block_size: usize,
    #[serde(rename = "read-capability")]
    pub read_capability: ReadCapabilityTest,
    pub urn: String,
    pub blocks: HashMap<String, String>,
    #[serde(rename = "type")]
    pub test_type: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NegativeTestVectorContent {
    pub id: u32,
    #[serde(rename = "spec-version")]
    pub spec_version: String,
    pub name: String,
    pub description: String,
    #[serde(rename = "read-capability")]
    pub read_capability: ReadCapabilityTest,
    pub urn: String,
    pub blocks: HashMap<String, String>,
}

#[derive(Debug)]
pub struct PositiveTestVector {
    pub file_name: String,
    pub data: PositiveTestVectorContent,
}

#[derive(Debug)]
pub struct NegativeTestVector {
    pub file_name: String,
    pub data: NegativeTestVectorContent,
}

pub fn read_positive_test_vectors() -> Vec<PositiveTestVector> {
    return std::fs::read_dir("./src/tests/eris-test-vectors")
        .unwrap()
        .map(|res_path| match res_path {
            Ok(path) => {
                if path.file_name().into_string().unwrap().ends_with(".json") {
                    let file = match std::fs::File::open(path.path()) {
                        Ok(f) => f,
                        Err(_) => return None,
                    };
                    let base_vector: BaseTestVectorContent = match serde_json::from_reader(file) {
                        Ok(v) => v,
                        Err(e) => {
                            panic!("Error reading vector {:?}: {}", path.file_name(), e)
                        }
                    };
                    match base_vector.test_type.as_str() {
                        "positive" => {
                            let file = match std::fs::File::open(path.path()) {
                                Ok(f) => f,
                                Err(_) => return None,
                            };
                            let vector: PositiveTestVectorContent =
                                match serde_json::from_reader(file) {
                                    Ok(v) => v,
                                    Err(e) => {
                                        panic!(
                                            "Error reading vector {:?}: {}",
                                            path.file_name(),
                                            e
                                        );
                                    }
                                };
                            return Some(PositiveTestVector {
                                data: vector,
                                file_name: String::from(path.path().file_name()?.to_str()?),
                            });
                        }
                        _ => return None,
                    }
                }
                return None;
            }
            Err(_) => {
                println!("Error reading test vectors");
                return None;
            }
        })
        .filter(|x| x.is_some())
        .map(|x| x.unwrap())
        .collect();
}

pub fn read_negative_test_vectors() -> Vec<NegativeTestVector> {
    return std::fs::read_dir("./src/tests/eris-test-vectors")
        .unwrap()
        .map(|res_path| match res_path {
            Ok(path) => {
                if path.file_name().into_string().unwrap().ends_with(".json") {
                    let file = match std::fs::File::open(path.path()) {
                        Ok(f) => f,
                        Err(_) => return None,
                    };
                    let base_vector: BaseTestVectorContent = match serde_json::from_reader(file) {
                        Ok(v) => v,
                        Err(e) => {
                            panic!("Error reading vector {:?}: {}", path.file_name(), e)
                        }
                    };
                    match base_vector.test_type.as_str() {
                        "negative" => {
                            let file = match std::fs::File::open(path.path()) {
                                Ok(f) => f,
                                Err(_) => return None,
                            };
                            let vector: NegativeTestVectorContent =
                                match serde_json::from_reader(file) {
                                    Ok(v) => v,
                                    Err(e) => {
                                        panic!(
                                            "Error reading vector {:?}: {}",
                                            path.file_name(),
                                            e
                                        );
                                    }
                                };
                            return Some(NegativeTestVector {
                                data: vector,
                                file_name: String::from(path.path().file_name()?.to_str()?),
                            });
                        }
                        _ => return None,
                    }
                }
                return None;
            }
            Err(_) => {
                println!("Error reading test vectors");
                return None;
            }
        })
        .filter(|x| x.is_some())
        .map(|x| x.unwrap())
        .collect();
}
