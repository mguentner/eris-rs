pub const REFKEY_SIZE_BYTES: usize = 32;
pub const REF_SIZE_BYTES: usize = REFKEY_SIZE_BYTES;
pub const KEY_SIZE_BYTES: usize = REFKEY_SIZE_BYTES;
pub const READ_CAPABILITY_URN_BYTES: usize = 1 + 1 + REF_SIZE_BYTES + KEY_SIZE_BYTES;