# NDN Based Multiparty Signing Protocol

**Author**: Zhiyi Zhang

**Versions**: v2 (Dec 23, 2020) obsolete v1 (Dec 15, 2020)

## Design Principles

* Each signed packet, including a not-yet-aggregated signed packet, should be identified by a different name (unique packet, unique name).
* The packets signed by signers can be merged into a single packet (that's why we use BLS).
* Each aggregated packet should refer the signing information to the scheme and other information so that a verfier has enough knowledge to know which keys should be used in verification (key info is needed for a signature with complex semantics).
* This library is a supporting library to multi-sign a packet based on the application needs, so our library aims to make minimum change to the application logic (e.g., name and content of packet to be signed).

## Overview

![Overview](protocol.jpg)

### Parties

In practice, a node can play more than one roles

* Initiator, `I`
* Signer, `S`
* Verifier, `V`

### Main workflow

* A party called initiator collects signatures from multiple signers with NDN based remote procedure call (RPC)
* The initiator verifies each returned signature and aggregates them with the original data into one signed data object
* The verifier verifies the data object

### Main design choices

* We utilize a new NDN based RPC to collect signatures from signers, modified from RICE (ICN 2019).
* We propose a new type of key locator to carry complicated signature information. In our case, is the schema and the exact keys involved in the signature signing.

### Assumptions

To perform a successful multiparty signature signing process:

* `S` takes the rules (schema) of the multiparty signature as input
* `V` knows the rules (schema) of verifying multiparty signature.
* A `S` can verify `I`'s request. This requires `S` can verify `I`'s identity, e.g., by installing its certificate in advance.
* `I` can verifie each `S`'s replied data. This requires `I` can verify each `S`'s identity, e.g., by installing each `S`'s certificate in advance.
* A `V` can verify the aggregated signature. This requires `V` can verify each involved signer's identity, e.g., by installing each `S`'s certificate in advance.

This library does not make assumptions on (i) how signers' certificates are installed to the initiator or verifier, (ii) how verifier knows and fetches the signed packet,  (iii) how verifier obtains the schema to decide whether a packet is trusted or not.

## Protocol Description

Packets:

* Unsigned Data packet, `D_Unsigned`
* A signed Data packet by `S1`, `D_Signed_S1`
* Aggregated signed data packet, `D_agg`
* Signing info file `D_info`

### Phase 1: Signature collection

---

**Input**: A scheme defined by the application.

**Output**: A sufficient number of signed packets replied from signers.

Phase 1 consists of multiple transactions between `I` and each `S` (`S`1 to `S`n).
Specifically, for each `I` and `S`, the protocol sets:

* `I` sends an Interest packet `SignRequest` to signer `S`. The packet is signed by I so that S can verifies I's identity and packet's authenticity.

  * Name: `/S/mps/sign/[hash]`
  * Application parameter:

    * `Unsigned_Wrapper_Name` + implicit digest, The name of a wrapper packet whose content is `D_Unsigned`. When the data object to be signed contains more than one packets, e.g., a large file, a manifest Data packet should be put here.
    * `KeyLocator_Name`, The key locator used in `S`'s signing process, which is the name of the signing info Data packet `D_info`, e.g., `/I/mps/schema/example/data/[version]`.
    * Optional `ForwardingHint`, the forwarding hint of the initiator.

  * Signature: Signed by `I`'s key

* `S` verifies the Interest packet and replies `Ack`, an acknowledgement of the request if `S` is available.

    * Name: `/S/mps/sign/[hash]`
    * Content:

      * `Status`, Status code: 200 OK, 500 Internal Error, 503 Unavailable
      * `Result_after`, Estimated time of finishing the signing process.
      * `Result_name`, the future result Data packet name `D_Signed_S.Name` (does not contain version, timestamp, or implicit digest).

    * Signature: Signed by `S`'s key

* `S` fetches the wrapper Data using the name in `SignRequest.Unsigned_Wrapper_Name`, verifies its digest against the implicit digest name component. If succeeds and `S` agrees to sign it, `S` uses its private key to sign the packet `D_Signed_S` and put the signature value into the result packet. Then, `S` publishes the result packet.

  * Data Name: `/S/mps/result-of/[hash]`
  * Data content:

    * Signature Value of `D_Signed_S`. Note the keylocator must be `SignRequest.KeyLocator_Name`

  * Signature info: SHA256 signature
  * Signature Value: SHA256

### Phase 2: Signature Aggregation

---

**Input**: A list of signed inner packets, `D_Signed_S1` to `D_Signed_Sn`.

**Output**: A single signed packet `D_agg`, a schema data packet for this `D_agg`.

After performing signature collection process with each `S` (in parallel to achieve high throughput), now `I` owns a list of signed inner packets, `D_Signed_S1` to `D_Signed_Sn`.

Now `I` will:

* Invoke the BLS function to aggregate all the signatures into one signature value
* Invoke the BLS function to aggregate all the involved public keys into one public key
* Generate `D_agg` by setting a `D_Unsigned` packet

  * Signature info: KeyType: BLS; KeyLocator: `SignRequest.KeyLocator_Name`
  * Signature value: the aggregated signature value

* Generate `D_info` packet

  * Data name: `SignRequest.KeyLocator_Name`
  * Data content:

    * `schema`, The schema
    * `signers`, The involved signer (if a k-out-of-n rule applies)
    * `pk_agg`, The aggregated public key

  * Signed by `I`

### Phase 3: Signature Verification

---

**Input**: A single signed packet `D_agg`.

**Output**: True/False (whether the signature is valid).

`V` fetches `D_agg`, extract its keylocator and fetches `D_info`.

* `V` first uses `D_info.pk_agg` to verify whether `D_agg` is correctly signed
* `V` then verifies `D_agg` is truly an aggregate of signer as indicated by `D_info.signers`
* `V` then check the `schema` against its own policies

If all the checks succeed, the signature is valid. Otherwise, invalid.
