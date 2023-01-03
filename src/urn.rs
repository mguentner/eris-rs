use crate::types::ReadCapability;

impl ReadCapability {
    pub fn to_urn(&self) -> String {
        let base32_alphabet = base32::Alphabet::RFC4648 { padding: false };
        let bytes = self.to_bytes();
        let read_capability_base32 = base32::encode(base32_alphabet, &bytes);
        return "urn:eris:".to_owned() + &read_capability_base32;
    }

    pub fn from_urn(urn: String) -> Option<ReadCapability> {
        let base32_alphabet = base32::Alphabet::RFC4648 { padding: false };
        match urn.split_once("urn:eris:") {
            Some((_, reference_base32)) => {
                match base32::decode(base32_alphabet, reference_base32) {
                    Some(bytes) => {
                        return ReadCapability::from_bytes(&bytes);
                    }
                    None => None,
                }
            }
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::vectors::read_positive_test_vectors;
    use std::convert::TryInto;

    #[test]
    fn encode() {
        let test_vectors = read_positive_test_vectors();
        for vector in test_vectors {
            println!("Running vector {}", vector.file_name);
            let capability: ReadCapability = vector.data.read_capability.try_into().unwrap();
            assert_eq!(capability.to_urn(), vector.data.urn);
        }
    }

    #[test]
    fn decode() {
        let test_vectors = read_positive_test_vectors();
        for vector in test_vectors {
            println!("Running vector {}", vector.file_name);
            let capability: ReadCapability = vector.data.read_capability.try_into().unwrap();

            let decoded_capability = ReadCapability::from_urn(vector.data.urn).unwrap();
            assert_eq!(capability, decoded_capability);
        }
    }
}
