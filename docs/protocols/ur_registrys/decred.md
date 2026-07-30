## Keystone Decred UR Registries

This protocol is based on the [Uniform Resources](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md). It describes the data schemas (UR Registries) used in Decred integrations.

### Introduction

Keystone's QR workflow involves two main steps: linking the wallet and signing data, broken down into three sub-steps:

1. **Wallet Linking:** Keystone displays the account extended public key as a Decred `dpub…` string in a QR code. The watch-only wallet imports it to track balances and build unsigned transactions.
2. **Transaction Creation:** The watch-only wallet creates an unsigned-transaction package and displays it as a `dcr-sign-request` UR for Keystone to scan, verify, and display. As of format version 2 the package must include the funding transaction for every input and the derivation path of every change output, so that the signer can verify the amounts and prove change ownership instead of trusting the companion. A watch-only wallet already has both from the chain, but it must retain the funding transactions rather than only the utxo amounts.
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

The `data` payload is a CBOR **array** (minicbor derive layout), **format version 2**:

```cddl
sign-request-package = [
    format_version: uint,      ; 2 — version 1 is REFUSED, see below
    tx_version: uint,          ; Decred tx version; MUST be 1
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
    prev_tx: [* uint],         ; REQUIRED: the serialized funding transaction
                               ; that created this prevout (prefix + witness)
]

output-meta = [
    value: int,                ; atoms
    version: uint,             ; script version; MUST be 0
    pk_script: [* uint],       ; output pkScript bytes
    is_change: bool,
    ? branch: uint,            ; REQUIRED iff is_change; 0 external / 1 internal
    ? index: uint,             ; REQUIRED iff is_change; address index
]
```

Encoding note: minicbor omits trailing absent optionals, so element counts vary
and a decoder must accept the short forms. A recipient output is a 4-element
array; a change output is 6. A package without `account_fp` is a 7-element array;
with it, 8. `prev_tx` is not optional in version 2 — it is the last element of
every `input-meta`, which is therefore always 9 elements.

### Why version 2 exists

Decred's signature hash does not commit to input amounts. In version 1 the only
source for an input's value was the companion's `value_in`, and a signer had no
way to check it. That is not a theoretical gap: dcrd's mempool **overwrites**
`ValueIn`, `BlockHeight` and `BlockIndex` from the utxo set before it computes the
fee (`internal/mempool/mempool.go`), so a companion that understated `value_in`
produced a review screen showing a small fee and a transaction that paid the
difference to the miner. Every number a version 1 signer could inspect was
internally consistent, so no device-side check could detect it.

Version 2 supplies the missing evidence:

* `prev_tx` lets the signer verify `value_in` and `prev_script` against a
  transaction hash it computes itself, rather than trusting an assertion.
* `branch`/`index` on change outputs let the signer prove ownership by deriving
  that one key, replacing a heuristic scan of a window of addresses guessed from
  the input indices. That scan misfiled change beyond the window as an external
  recipient and simultaneously reported it as evidence of a hostile companion —
  against an address that belonged to the user.

**Version 1 packages are refused, not accepted on a reduced-trust path.** The
sender chooses the version, so a signer that still accepted version 1 would let a
hostile companion opt out of verification entirely and the attack above would
remain fully exploitable. Verification is worth only as much as the refusal of
unverified packages.

### Verification a signer MUST perform

Decred has no PSBT; this package carries everything the offline signer needs, and
all of it is untrusted input. A conforming signer MUST refuse the package unless
every one of the following holds. None of these require key material except where
noted, so a signer can reject before prompting for a password.

Structural:

1. `format_version` equals 2.
2. `tx_version` equals 1. Only version 1 is standard, and DCP0008 caps the
   consensus version at 3, so anything else assembles into a transaction the
   network will not mine.
3. Every output's `version` is 0. DCP0008 rejects a regular-transaction output
   with a higher script version (`ErrScriptVersionTooHigh`), so signing one
   produces a transaction that can never confirm.
4. Inputs and outputs are both non-empty and within the signer's package caps.
5. For every input: `tree` is 0, `branch` is 0 or 1, and `index` is below 2^31
   (non-hardened).
6. For every output: `branch` and `index` are either both present or both absent;
   their presence equals `is_change`; and when present, `branch` is 0 or 1 and
   `index` is below 2^31.
7. No two inputs name the same outpoint (`prev_hash`, `prev_index`, `tree`).
   Duplicates inflate the apparent input total and understate the displayed fee.
8. Every amount is in `(0, MaxAmount]` for inputs and `[0, MaxAmount]` for
   outputs, sums are computed without overflow, and the input total is at least
   the output total. `MaxAmount` is 21,000,000 DCR in atoms.

Fee policy, which a companion must respect or its transactions will be refused:
a fee above `FEE_ALWAYS_ALLOWED_ATOMS` (100,000 atoms, 0.001 DCR) is rejected when
it also exceeds `1 / MAX_FEE_FRACTION_DIVISOR` (currently 1/20, i.e. 5%) of the
input total. The absolute floor exists so dust consolidation, where the fee is
legitimately a large share of a small total, still works. Note this ceiling is
only meaningful *because* of the `prev_tx` verification above — applied to version
1's asserted amounts it bounded nothing, since the understatement attack declares
a small fee and the real one materialises only after dcrd substitutes the true
values.

Package caps: at most 1000 inputs and 1000 outputs, so a hostile package cannot
make a small device grind or allocate without bound.

Amount verification, per input:

9. `prev_tx` is present and parses as a Decred transaction.
10. Its transaction hash equals `prev_hash`. Note the hash rule: a Decred txid is
    a **single** BLAKE-256 over the **prefix** serialization — not a double hash,
    and not over the full serialization. (Double BLAKE-256 is used for the
    base58check address checksum, which is a different thing.)
11. `prev_tx` has an output at `prev_index`, and that output's value equals
    `value_in` and its `pk_script` equals `prev_script`.

Ownership, requiring the account public key:

12. Every input's `prev_script` equals the P2PKH script of the public key derived
    at `m/44'/42'/account'/branch/index`. An input the wallet cannot derive is
    refused.
13. An output counts as change **only** if the key derived at its `branch`/`index`
    produces exactly its `pk_script`. A supplied path that does not derive to the
    output is a hard refusal, not a warning — so a recipient can never be
    disguised as change. An output with no path is treated as an external
    recipient and included in the amount the user approves; a companion that
    omits the path for an output that really is the wallet's own therefore
    over-states the send rather than hiding it.

Because ownership is proven rather than guessed, there is no longer a
"mislabelled change" warning state: the condition cannot reach the review screen.

If the optional `account_fp` is present and does not match the device's account,
the request is refused up front with a "different wallet or account" message — a
courtesy check only; the verification above remains the fund protector.

### Implementation status

`dcr-rs` implements version 2 as specified here. The KeyOS/Passport Prime
`decred-core` implementation still speaks version 1 and must be updated before
the two are interoperable again; until then, treat cross-device agreement on the
version 2 byte layout as unverified. The layout regression test in `dcr-rs`
(`cbor_layout_pins_v2_encoding`) is generated by `dcr-rs` itself and should be
regenerated from `decred-core` once that side lands, restoring it to a genuine
cross-implementation check.

### CDDL for Decred Signed Transaction

```cddl
dcr-signed-tx = {
    data: bytes, ; full (prefix + witness) serialized Decred transaction, ready to broadcast
}
```

Registry type: `dcr-signed-tx`, tag 8702.
