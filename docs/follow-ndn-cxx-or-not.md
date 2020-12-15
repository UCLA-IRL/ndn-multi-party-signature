# Should the NDN-MPS be strictly integrated into the existing ndn-cxx::KeyChain framework?

**Issue description**: When designing the new library (NDN-multiparty-signature, NDN-MPS in short), we encountered a selection choice question.

* **Choice 1**: realize the new signature scheme and the storage of keys under the existing framework as defined in ndn-cxx::KeyChain.
* **Choice 2**: realize our own signature scheme and signing APIs and delegate storage to further libraries/applications.

To help make a better choice, I did some discussion for each topic to compare these two choices.

## Comparison

### 1. Choice 1: Use the existing TPM integration in ndn-cxx for secure storage of private keys

The fact is that the currently TPM backend implementation in ndn-cxx (ndn-cxx/security/tpm/impl) cannot be extended to support a new key type, in our case, the BLS private key.
To add BLS key, we need to implement a new TPM backend class by ourselves and we cannot do this by inheriting existing TPM backend classes because all the virtual functions are marked with `final` keywords (a C++ keyword preventing a member function from overriding).

<span style="color:blue"> **Conclusion**: Existing TPM code cannot be reused. A brand-new TPM impl following ndn-cxx's abstraction of TPM backend is needed. </span>

### 2. Related: Choice 2 does not consider the secure storage of keys

This is mainly a response to Lixia's comment on taking key bits as parameters in APIs.

The APIs exposed by existing well-known crypto codebases (e.g., boringssl, openssl, sodium) also take raw key bits (data structures wrapped raw key bits) as parameters.
To be used with a TPM, it is the TPM provider or third-party programmers (not belong to crypto library nor TPM provider) who integrate these libraries into the TPM.
For example, by invoking APIs (i.e., code pieces) within the TPM to ensure the code is running correctly.

In fact, this allows a maximum generality for these libraries because the form of raw key bits can be merged in or easily modified by users of the library.
Also, to achieve a better generality, our library shouldn't be tangled with a specific backend implemented by ourselves, because this will prevent users who has another TPM from using the library.
For example, they need to write a new TPM backend class for their TPM following ndn-cxx's TPM abstraction.

<span style="color:blue"> **Conclusion**: Not coupling with our own TPM can improve generality.
Later, when this codebase is used by Operant's project, their TPM implementation can utilize the code in our library and update the signing/verification functions by delegating to the TPM instead of using raw key bits. </span>

### 3. Choice 1: reuse the existing KeyChain APIs to do signing

As mentioned in the first discussion, to add the new key type, a new TPM backend impl is needed.
Therefore, a new KeyChain instance is needed (which is different from the one used by `ndnsec` command line tools) and the users, in any case, will need to re-instantiate the KeyChain and use this new instance to sign.

<span style="color:blue"> **Conclusion**: APIs must be called from a new instance of KeyChain. </span>

### 4. Choice 2: needs a redo of encoding/decoding for signature and packets

If we do not go with ndn-cxx::KeyChain, we need to provide our own APIs for BLS signing.

However, since the NDN Data class and Signature class provides usable setters, we don't really need to redo the encoding/decoding of Data packets. Just simple high-level setting is enough.

<span style="color:blue"> **Conclusion**: Some high-level code is required but low-level encoding is not needed. </span>

## About validation

The validation can be realized by inheriting ndn-cxx::validator and to support our own schema.