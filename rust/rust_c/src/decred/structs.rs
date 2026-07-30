use crate::common::{
    ffi::VecFFI,
    free::Free,
    types::{Ptr, PtrString},
    utils::convert_c_char,
};
use crate::{free_str_ptr, free_vec, impl_c_ptr, impl_c_ptrs};
use alloc::string::String;
use alloc::vec::Vec;
use app_decred::{DisplayItem, ParsedDcrTx};
use cstr_core;

#[repr(C)]
pub struct DisplayDcrTx {
    pub network: PtrString,
    pub total_send_value: PtrString,
    pub total_input_value: PtrString,
    pub total_output_value: PtrString,
    pub fee_value: PtrString,
    pub from: Ptr<VecFFI<DisplayDcrTxItem>>,
    pub to: Ptr<VecFFI<DisplayDcrTxItem>>,
    pub change: Ptr<VecFFI<DisplayDcrTxItem>>,
    /// Lock time as a decimal string, or NULL when zero. The C side must check for
    /// NULL and omit the row.
    pub lock_time: PtrString,
    /// Expiry height as a decimal string, or NULL when zero. See
    /// `ParsedDcrTx::expiry` for why this is worth showing.
    pub expiry: PtrString,
}

impl From<&ParsedDcrTx> for DisplayDcrTx {
    fn from(tx: &ParsedDcrTx) -> Self {
        let items = |v: &Vec<DisplayItem>| -> Ptr<VecFFI<DisplayDcrTxItem>> {
            VecFFI::from(v.iter().map(DisplayDcrTxItem::from).collect::<Vec<_>>()).c_ptr()
        };
        // An absent field crosses as NULL rather than an empty string, so the C side
        // can omit the row with a plain NULL check. free_str_ptr! is NULL-tolerant.
        let opt_str = |v: &Option<String>| -> PtrString {
            match v {
                Some(s) => convert_c_char(s.clone()),
                None => core::ptr::null_mut(),
            }
        };
        Self {
            network: convert_c_char(tx.network.clone()),
            total_send_value: convert_c_char(tx.total_send_value.clone()),
            total_input_value: convert_c_char(tx.total_input_value.clone()),
            total_output_value: convert_c_char(tx.total_output_value.clone()),
            fee_value: convert_c_char(tx.fee_value.clone()),
            from: items(&tx.from),
            to: items(&tx.to),
            change: items(&tx.change),
            lock_time: opt_str(&tx.lock_time),
            expiry: opt_str(&tx.expiry),
        }
    }
}

impl Free for DisplayDcrTx {
    unsafe fn free(&self) {
        free_str_ptr!(self.network);
        free_str_ptr!(self.total_send_value);
        free_str_ptr!(self.total_input_value);
        free_str_ptr!(self.total_output_value);
        free_str_ptr!(self.fee_value);
        free_vec!(self.from);
        free_vec!(self.to);
        free_vec!(self.change);
        free_str_ptr!(self.lock_time);
        free_str_ptr!(self.expiry);
    }
}

#[repr(C)]
pub struct DisplayDcrTxItem {
    pub address: PtrString,
    pub value: PtrString,
}

impl From<&DisplayItem> for DisplayDcrTxItem {
    fn from(item: &DisplayItem) -> Self {
        Self {
            address: convert_c_char(item.address.clone()),
            value: convert_c_char(item.value.clone()),
        }
    }
}

impl Free for DisplayDcrTxItem {
    unsafe fn free(&self) {
        free_str_ptr!(self.address);
        free_str_ptr!(self.value);
    }
}

impl_c_ptrs!(DisplayDcrTx, DisplayDcrTxItem);
