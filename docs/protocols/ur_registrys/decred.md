## Keystone Decred UR Registries

This protocol is based on the [Uniform Resources](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md). It describes the data schemas (UR Registries) used in Decred integrations.

### Introduction

Keystone's QR workflow involves two main steps: linking the wallet and signing data, broken down into three sub-steps:

1. **Wallet Linking:** Keystone displays the account extended public key as a Decred `dpub…` string in a QR code. The watch-only wallet imports it to track balances and build unsigned transactions.
2. **Transaction Creation:** The watch-only wallet creates an unsigned-transaction package and displays it as a `dcr-sign-request` UR for Keystone to scan, verify, and display.
3. **Signing Authorization:** Keystone signs the transaction and displays the broadcast-ready result as a `dcr-signed-tx` UR for the watch-only wallet to scan and broadcast.

### Decred Accounts

Keystone derives the Decred account at `m/44'/42'/0'` (SLIP-0044 coin type 42) and serializes the account extended public key with the mainnet `dpub` version bytes (`0x02fda926`) and Decred's double-BLAKE256 base58check checksum. Receive addresses are v0 P2PKH (`Ds…`) at `m/44'/42'/0'/0/i`; change lives on branch 1.

### CDDL for Decred Sign Request

```cddl
dcr-sign-request = {
    data: bytes, ; the unsigned-transaction package (see below)
}
```

Registry type: `dcr-sign-request`, tag 8701.

The `data` payload is a CBOR **array** (minicbor derive layout, shared byte-for-byte
with the KeyOS/Passport Prime `decred-core` implementation, format version 1):

```cddl
sign-request-package = [
    format_version: uint,      ; 1
    tx_version: uint,          ; Decred tx version, usually 1
    account: uint,             ; BIP44 account (hardened index without the flag)
    lock_time: uint,
    expiry: uint,
    inputs: [+ input-meta],
    outputs: [+ output-meta],
    ? account_fp: [4*4 uint],  ; OPTIONAL: BIP32 fingerprint of the account the
                               ; request was built against (first 4 bytes of
                               ; hash160 of the account's compressed pubkey)
]

input-meta = [
    prev_hash: [32*32 uint],   ; previous outpoint hash (internal byte order)
    prev_index: uint,
    tree: uint,                ; 0 = regular tree (the only tree Keystone signs)
    sequence: uint,
    value_in: int,             ; atoms
    branch: uint,              ; 0 external / 1 internal
    index: uint,               ; address index below the account
    prev_script: [* uint],     ; prevout pkScript bytes
]

output-meta = [
    value: int,                ; atoms
    version: uint,             ; script version, usually 0
    pk_script: [* uint],       ; output pkScript bytes
    is_change: bool,
]
```

Decred has no PSBT; this package carries everything the offline signer needs.
The package is untrusted input: Keystone re-derives every input's key from
`branch`/`index` and refuses to sign unless the claimed `prev_script` matches,
and it re-classifies every output itself (change vs recipient) instead of
believing `is_change`. A mislabelled output is surfaced as a tamper warning.
If the optional `account_fp` is present and does not match the device's
account, the request is refused up front with a "different wallet or account"
message — a courtesy check only; the `prev_script` re-derivation remains the
fund protector. Packages without the field (the original 7-element layout)
remain fully supported.

### CDDL for Decred Signed Transaction

```cddl
dcr-signed-tx = {
    data: bytes, ; full (prefix + witness) serialized Decred transaction, ready to broadcast
}
```

Registry type: `dcr-signed-tx`, tag 8702.
