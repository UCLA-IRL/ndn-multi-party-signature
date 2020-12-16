# NDN Based Multiparty Signing Protocol

**Author**: Zhiyi Zhang

**Current Version**: Dec 15, 2020

## Design Principles

* Each signed packet, including a not-yet-aggregated signed packet, should be identified by a different name (unique packet, unique name).
* The packets signed by signers can be merged into a single packet (that's why we use BLS).
* Each aggregated packet should refer the signing information to the scheme and other information so that a verfier has enough knowledge to know which keys should be used in verification (key info is needed for a signature with complex semantics).

## Overview

![image](protocol.jpg)

## Protocol Description

Roles (in practice, a node can play more than one roles):

* Initiator, `I`
* Signer, `S`
* Verifier, `V`

Packets:

* Unsigned Data packet, `D_Unsigned`
* A Data packet signed by `S`1, `D_S1`
* Aggregated signed data packet, `D_agg`
* Signing info file `D_info`

Prerequisites of a successful multiparty signature signing process:

* A `S` can verify `I`'s request. This requires `S` can verify `I`'s identity, e.g., by installing its certificate in advance.
* A `V` can verify the aggregated signature. This requires `V` can verifies each involved signer's identity, e.g., by installing each `S`'s certificate in advance.

### Phase 1: Signature collection

**Input**: A scheme defined by the application.

**Output**: A sufficient number of signed packets replied from signers.

Phase 1 consists of multiple transactions between `I` and each `S` (`S`1 to `S`n).
Specifically, for each `I` and `S`, the protocol sets:

* `I` sends an Interest packet `Int1` to signer `S`. The packet is signed by I so that S can verifies I's identity and packet's authenticity.

  - Name: `/S/mps/sign/[hash]`
  - Application parameter:

    + `Name_D_Unsigned`, The name of the `D_Unsigned`, e.g., `/example/data`. When the data object contains more than one packets, e.g., a large file, a manifest Data packet should be put here.
    + `Sha256_D_Unsigned`, The hash of the `D_Unsigned`.
    + `KeyLocator_Name`, The key locator used in `S`'s signing process, which is the name of the signing info Data packet `D_info`, e.g., `/I/mps/schema/example/data/[version]`.

  - Signature: Signed by `I`'s key

* `S` verifies the Interest packet, fetches the `Int1.D_Unsigned`, verifies its hash against `Int1.Sha256_D_Unsigned`. If success and `S`'s application logic agrees to sign it, `S` uses its private key `sk_S` to sign the packet and encapsulate it into a wrapper Data packet `Dat1`. `S` replies `Dat1` backs to `I`

  - Data Name: `/S/mps/sign/[hash]`
  - Data content:

    + Data Name: `Int1.Name_D_Unsigned`, e.g., `/example/data`
    + Data content
    + Signature Info: KeyType: BLS; KeyLocator: `Int1.KeyLocator_Name`
    + Signature Value

  - Signature info: SHA256 signature
  - Signature Value: SHA256

### Phase 2: Signature Aggregation

**Input**: A list of signed inner packets, `D_S1` to `D_Sn`.

**Output**: A single signed packet `D_agg`, a schema data packet for this `D_agg`.

After performing signature collection process with each `S` (in parallel to achieve high throughput), now `I` owns a list of signed inner packets, `D_S1` to `D_Sn`.

Now `I` will:

* Invoke the BLS function to aggregate all the signatures into one signature value
* Invoke the BLS function to aggregate all the involved public keys into one public key
* Generate `D_agg` by setting a `D_Unsigned` packet

  - Signature info: KeyType: BLS; KeyLocator: `Int1.KeyLocator_Name`
  - Signature value: the aggregated signature value

* Generate `D_info` packet

  - Data name: `Int1.KeyLocator_Name`
  - Data content:

    + `schema`, The schema
    + `signers`, The involved signer (if a k-out-of-n rule applies)
    + `pk_agg`, The aggregated public key

  - Signed by `I`

### Phase 3: Signature Verification

**Input**: A single signed packet `D_agg`.

**Output**: True/False (whether the signature is valid).

`V` fetches `D_agg`, extract its keylocator and fetches `D_info`.

* `V` first uses `D_info.pk_agg` to verify whether `D_agg` is correctly signed
* `V` then verifies `D_agg` is truly an aggregate of signer as indicated by `D_info.signers`
* `V` then check the `schema` against its own policies

If all the checks succeed, the signature is valid. Otherwise, invalid.