use blake2b_simd::Params;
use crate::constants::{REFKEY_SIZE_BYTES, REF_SIZE_BYTES, KEY_SIZE_BYTES};

pub mod types;
pub mod constants;
pub mod urn;
pub mod encode;
pub mod decode;

fn arity(block_size_bytes: usize) -> usize {
    if (block_size_bytes % (REF_SIZE_BYTES + KEY_SIZE_BYTES)) != 0 {
        panic!(
            "block size ({}) must be a multiple of {}",
            block_size_bytes,
            REF_SIZE_BYTES + KEY_SIZE_BYTES
        );
    }
    return block_size_bytes / (REF_SIZE_BYTES + KEY_SIZE_BYTES);
}

fn blake2b256_hash(input: &[u8], key: Option<&[u8]>) -> [u8; REFKEY_SIZE_BYTES] {
    let mut hasher = match key {
        Some(k) => Params::new().hash_length(32).key(k).to_state(),
        None => Params::new().hash_length(32).to_state(),
    };
    hasher.update(input);
    let mut result: [u8; REFKEY_SIZE_BYTES] = Default::default();
    result.copy_from_slice(hasher.finalize().as_bytes());
    return result;
}

#[cfg(test)]
mod tests {
    pub mod vectors;
}
