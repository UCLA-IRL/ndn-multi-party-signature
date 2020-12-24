# Integrate Multiparty Trust into NDNCERT revocation with DLedger: A Roadmap

**Author**: Zhiyi Zhang

**Version**: Updated in Dec 23, 2020; Nov 18, 2020

## An overview

| Task | Description | Estimated Time |
|:----:|:-----------:|:--------------:|
|  1  | Prepare Multiparty Signature Library | 3～4 weeks |
|  2  | Integrate multiparty signature into NDNCERT | 2 weeks |
|  3  | Integrate test with DLedger | 2 weeks |

**Time in total**: 2 months

**Starting date**: The start of the Spring quarter of UCLA

**Members**: Zhiyi Zhang, Siqi Liu

**Advisor**: Lixia Zhang

## Step 1: Prepare Multiparty Signature Library

* **Goal**

  Ensure the multiparty signature can be utilized correctly

* **Estimated time**

  2 weeks

* **Deliverable**

  C++ BLS signature library for NDN: `ndn-bls`

  * Dependencies: ndn-cxx (ndn-ind), [BLS library](https://github.com/herumi/bls)
  * Platform: cross-platform
  * With tests: Yes

* **Remarks**

  After reading the code of the project from CS217, I found many quick and dirty tricks were used.
  One typical example is that they put the BLS logic into the exception handling logic, which can cause many problems later.
  In addition, there are several important missing components: a protocol to allow multiple party to sign the message, the schema to specify verification policies, and the public key storage.
  I believe making a separate codebase to handle BLS can save more time in the future and benefit other NDN-based projects as well.

### Step 1.1: Migrate BLS patch out to be a separate library

* **Goal**

  1. Extract the logic from the CS 217 project and make it a separate library.
  2. Add a certificate storage based on file to keep trusted public keys.
  3. Add a schema format to specify the rules used for verification
  An example:

     ```ascii
     Prefix: /data
     Signed-by:
       ALL-OF
         /a/KEY/_/_
         /b/KEY/_/_
       AT-LEAST 2:
         /c/KEY/_/_
         /d/KEY/_/_
         /e/KEY/_/_
     ```

  4. Add a protocol for a initiator to contact different signers to jointly sign a message.

* **Estimated time**

  2-3 week

### Step 1.2: Exercise the BLS library

* **Goal**

  Add unit tests for the library to make sure

  1. the encoding/decoding is correct
  2. the signature can be successfully signed and verified
  3. the certificate storage can work as expected
  4. the configuration works correctly

* **Estimated time**

  1 week

## Step 2: Integrate multiparty signature into NDNCERT

* **Goal**

  Allow NDNCERT to use `ndn-bls` to verify the signature provided by the requester in order to obtain/revoke a certificate.

* **Estimated time**

  2 weeks

* **Deliverable**

  NDNCERT library with new feature supported

  * When compile with flag `--with-multiparty-trust`, the new challenge will be compiled and `ndn-bls` library with be linked.

### Step 2.1: Create a new challenge utilizing multiparty signature

* **Goal**

  1. Add new flag for `ndn-bls`
  2. Add new challenge
  3. Test the new challenge

* **Estimated time**

  1 week

### Step 2.2: Integrate test

* **Goal**

  Integrate test the NDNCERT with multiparty signature challenge to ensure the system works as expected.

* **Estimated time**

  1 week

## Step 3: Integrate test with DLedger

* **Goal**

  Integrate test of NDNCERT's multiparty signature challenge with DLedger.

* **Estimated time**

  2 week