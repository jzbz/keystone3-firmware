//! Decred Signed Transaction Registry Type
//!
//! The response half of the Decred QR signing flow: after the user approves,
//! the device returns the fully signed, broadcast-ready Decred transaction
//! (full serialization, prefix + witness) for the watch-only companion to
//! broadcast.
//!
//! The structure follows the UR Registry Type specification with a map
//! containing:
//! - Data: the raw signed transaction bytes

use alloc::string::ToString;
use minicbor::data::Int;

use crate::{
    cbor::cbor_map,
    impl_template_struct,
    registry_types::{RegistryType, DCR_SIGNED_TX},
    traits::{MapSize, RegistryItem},
    types::Bytes,
};

const DATA: u8 = 1;

impl_template_struct!(DcrSignedTx { data: Bytes });

impl MapSize for DcrSignedTx {
    fn map_size(&self) -> u64 {
        1
    }
}

impl RegistryItem for DcrSignedTx {
    fn get_registry_type() -> RegistryType<'static> {
        DCR_SIGNED_TX
    }
}

impl<C> minicbor::Encode<C> for DcrSignedTx {
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

impl<'b, C> minicbor::Decode<'b, C> for DcrSignedTx {
    fn decode(d: &mut minicbor::Decoder<'b>, _ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        let mut result = DcrSignedTx::default();
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

    #[test]
    fn test_dcr_signed_tx_encode_decode() {
        let data = hex::decode("01000000015e670e5fca4477bf3d5b1e4b7e93d2437ac6e848").unwrap();

        let tx = DcrSignedTx { data };

        let cbor = minicbor::to_vec(&tx).unwrap();
        let decoded: DcrSignedTx = minicbor::decode(&cbor).unwrap();

        assert_eq!(decoded.data, tx.data);
    }

    #[test]
    fn test_registry_type() {
        assert_eq!(DcrSignedTx::get_registry_type().get_type(), "dcr-signed-tx");
    }
}
