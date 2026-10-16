//! Serde for byte strings: raw bytes in binary formats (postcard), unpadded base64url text in
//! human-readable ones (JSON, e.g. `keyring.json` and the JSON form of session messages).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserializer, Serializer, de};

pub(crate) fn serialize<T: AsRef<[u8]>, S: Serializer>(v: &T, s: S) -> Result<S::Ok, S::Error> {
    if s.is_human_readable() { s.serialize_str(&URL_SAFE_NO_PAD.encode(v.as_ref())) } else { s.serialize_bytes(v.as_ref()) }
}

pub(crate) fn deserialize<'de, T: TryFrom<Vec<u8>>, D: Deserializer<'de>>(d: D) -> Result<T, D::Error> {
    struct Bytes;
    impl<'de> de::Visitor<'de> for Bytes {
        type Value = Vec<u8>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("bytes or base64url text")
        }
        fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
            Ok(v.to_vec())
        }
        fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
            Ok(v)
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<u8>, E> {
            URL_SAFE_NO_PAD.decode(v).map_err(E::custom)
        }
        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
            let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(4096));
            while let Some(b) = seq.next_element::<u8>()? {
                out.push(b);
            }
            Ok(out)
        }
    }
    let bytes = if d.is_human_readable() { d.deserialize_str(Bytes)? } else { d.deserialize_byte_buf(Bytes)? };
    let len = bytes.len();
    T::try_from(bytes).map_err(|_| de::Error::invalid_length(len, &"the expected number of bytes"))
}
