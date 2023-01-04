use crate::constants::{KEY_SIZE_BYTES, READ_CAPABILITY_URN_BYTES, REF_SIZE_BYTES};
use std::convert::TryFrom;
use std::convert::TryInto;

pub type Reference = [u8; REF_SIZE_BYTES];
pub type Key = [u8; KEY_SIZE_BYTES];

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct ReferenceKeyPair {
    pub reference: Reference,
    pub key: Key,
}

pub struct BlockWithReference {
    pub block: Vec<u8>,
    pub reference: Reference,
}

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum BlockSize {
    Size1KiB,
    Size32KiB,
}

const BLOCK_SIZE_1KIB: u8 = 0x0a;
const BLOCK_SIZE_32KIB: u8 = 0x0f;

impl TryFrom<u8> for BlockSize {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            BLOCK_SIZE_1KIB => Ok(BlockSize::Size1KiB),
            BLOCK_SIZE_32KIB => Ok(BlockSize::Size32KiB),
            _ => Err(()),
        }
    }
}

impl Into<u8> for BlockSize {
    fn into(self) -> u8 {
        match self {
            BlockSize::Size1KiB => BLOCK_SIZE_1KIB,
            BlockSize::Size32KiB => BLOCK_SIZE_32KIB,
        }
    }
}

impl TryFrom<usize> for BlockSize {
    type Error = ();

    fn try_from(v: usize) -> Result<Self, Self::Error> {
        match v {
            1024 => Ok(BlockSize::Size1KiB),
            32768 => Ok(BlockSize::Size32KiB),
            _ => Err(()),
        }
    }
}

impl Into<usize> for BlockSize {
    fn into(self) -> usize {
        match self {
            BlockSize::Size1KiB => 1024,
            BlockSize::Size32KiB => 32768,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct ReadCapability {
    pub block_size: BlockSize,
    pub level: u8,
    pub root: ReferenceKeyPair,
}

impl ReadCapability {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::with_capacity(READ_CAPABILITY_URN_BYTES);
        res.resize(READ_CAPABILITY_URN_BYTES, 0);
        res[0] = self.block_size.into();
        res[1] = self.level;
        res[2..34].copy_from_slice(&self.root.reference);
        res[34..].copy_from_slice(&self.root.key);
        res
    }

    pub fn from_bytes(data: &[u8]) -> Option<ReadCapability> {
        if data.len() != (REF_SIZE_BYTES + KEY_SIZE_BYTES + 2) {
            return None;
        }
        match data[0].try_into() {
            Ok(block_size) => {
                let level = data[1];
                let mut reference: [u8; REF_SIZE_BYTES] = Default::default();
                let mut key: [u8; KEY_SIZE_BYTES] = Default::default();
                key.copy_from_slice(&data[34..66]);
                reference.copy_from_slice(&data[2..34]);
                let root = ReferenceKeyPair { reference, key };
                Some(ReadCapability {
                    block_size,
                    level,
                    root,
                })
            }
            Err(_) => None,
        }
    }
}

pub type BlockStorageError = std::io::Error;
pub type BlockStorageErrorKind = std::io::ErrorKind;
pub type BlockStorageGetFn = dyn Fn(Reference) -> Result<Vec<u8>, BlockStorageError>;
pub type BlockWithReferenceWriteFn = dyn Fn(BlockWithReference) -> Result<usize, BlockStorageError>;
pub type NodeParsingError = std::io::Error;
pub type NodeParsingErrorKind = std::io::ErrorKind;
