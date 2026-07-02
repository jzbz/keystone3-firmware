//! Decred Sign Request Registry Type
//!
//! This module implements the CBOR encoding and decoding for Decred sign
//! requests. Decred has no PSBT; the payload here is the compact CBOR
//! "unsigned-tx package" produced by a watch-only companion wallet (inputs
//! with prevout metadata and derivation branch/index, outputs with pkScript
//! and change flags). The device re-derives every script itself before
//! displaying or signing, so the package is untrusted input.
//!
//! The structure follows the UR Registry Type specification with a map
//! containing:
//! - Data: the raw sign-request package bytes

use alloc::string::ToString;
use minicbor::data::Int;

use crate::{
    cbor::cbor_map,
    impl_template_struct,
    registry_types::{RegistryType, DCR_SIGN_REQUEST},
    traits::{MapSize, RegistryItem},
    types::Bytes,
};

const DATA: u8 = 1;

impl_template_struct!(DcrSignRequest { data: Bytes });

impl MapSize for DcrSignRequest {
    fn map_size(&self) -> u64 {
        1
    }
}

impl RegistryItem for DcrSignRequest {
    fn get_registry_type() -> RegistryType<'static> {
        DCR_SIGN_REQUEST
    }
}

impl<C> minicbor::Encode<C> for DcrSignRequest {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.map(self.map_size())?;

        e.int(Int::from(DATA))?.bytes(&self.data)?;

        Ok(())
    }
}

impl<'b, C> minicbor::Decode<'b, C> for DcrSignRequest {
    fn decode(d: &mut minicbor::Decoder<'b>, _ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        let mut result = DcrSignRequest::default();
        cbor_map(d, &mut result, |key, obj, d| {
            let key =
                u8::try_from(key).map_err(|e| minicbor::decode::Error::message(e.to_string()))?;
            match key {
                DATA => {
                    obj.data = d.bytes()?.to_vec();
                }
                _ => {}
            }
            Ok(())
        })?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_dcr_sign_request_encode_decode() {
        let data = hex::decode("a70001010102000318640419053904c8").unwrap();

        let request = DcrSignRequest { data };

        let cbor = minicbor::to_vec(&request).unwrap();
        let decoded: DcrSignRequest = minicbor::decode(&cbor).unwrap();

        assert_eq!(decoded.data, request.data);
    }

    #[test]
    fn test_registry_type() {
        assert_eq!(
            DcrSignRequest::get_registry_type().get_type(),
            "dcr-sign-request"
        );
    }
}
