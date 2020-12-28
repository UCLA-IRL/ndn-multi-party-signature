#include <set>
#include "ndnmps/players.hpp"
#include "ndnmps/common.hpp"

namespace ndn {

static bool BLS_INITIALIZED = false;

void
bls_library_init() {
    if (!BLS_INITIALIZED) {
        int err = blsInit(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
        if (err != 0) {
            printf("blsInit err %d\n", err);
            exit(1);
        } else {
            BLS_INITIALIZED = true;
        }
    }
}

Signer::Signer()
{
    bls_library_init();
    blsSecretKeySetByCSPRNG(&m_sk);
    blsGetPublicKey(&m_pk, &m_sk);
}

Signer::Signer(Buffer secretKeyBuf)
{
    bls_library_init();
    auto ret = blsSecretKeyDeserialize(&m_sk, secretKeyBuf.data(), secretKeyBuf.size());
    if (ret == 0) {
        NDN_THROW(std::runtime_error("Fail to read secret key in Signer::initKey()"));
    }
    blsGetPublicKey(&m_pk, &m_sk);
}

blsPublicKey
Signer::getPublicKey()
{
    return m_pk;
}

std::vector<uint8_t>
Signer::getpublicKeyStr()
{
    int size = blsGetSerializedPublicKeyByteSize();
    std::vector<uint8_t> outputBuf(size);
    int written_size = blsPublicKeySerialize(outputBuf.data(), outputBuf.size(), &m_pk);
    if (written_size == 0) {
        NDN_THROW(std::runtime_error("Fail to write public key in Signer::getpublicKeyStr()"));
    }
    outputBuf.resize(written_size);
    return std::move(outputBuf);
}

Block
Signer::getSignature(Data data, const SignatureInfo& sigInfo)
{
    if (sigInfo.getSignatureType() != tlv::SignatureSha256WithBls) {
        NDN_THROW(std::runtime_error("Signer got non-BLS signature type"));
    }

    data.setSignatureInfo(sigInfo);

    EncodingBuffer encoder;
    data.wireEncode(encoder, true);

    blsSignature sig;
    blsSign(&sig, &m_sk, encoder.buf(), encoder.size());
    auto signatureBuf = make_shared<Buffer>(blsGetSerializedSignatureByteSize());
    blsSignatureSerialize(signatureBuf->data(), signatureBuf->size(), &sig);

    return Block(tlv::SignatureValue, signatureBuf);
}

Verifier::Verifier()
{
    bls_library_init();
}

void
Verifier::addCert(const Name& keyName, blsPublicKey pk)
{
    m_certs.emplace(keyName, pk);
}

bool
Verifier::verifySignature(const Data& data, const MultipartySchema& schema)
{
    auto sigInfo = data.getSignatureInfo();
    auto locatorBlock = sigInfo.getCustomTlv(tlv::MultiPartyKeyLocator);
    if (!locatorBlock) return false;
    auto locator = MultiPartyKeyLocator(*locatorBlock);
    if (!verifyKeyLocator(locator, schema)) return false;

    //check signature
    std::vector<blsPublicKey> keys;
    for (const auto& signer: locator.getLocators()) {
        auto it = m_certs.find(signer.getName());
        if (it == m_certs.end()) return false;
        keys.emplace_back(it->second);
    }

    //get signature value
    auto sigValue = data.getSignatureValue();
    blsSignature sig;
    if (blsSignatureDeserialize(&sig, sigValue.value(), sigValue.value_size()) == 0) return false;

    EncodingBuffer encoder;
    data.wireEncode(encoder, true);

    return blsFastAggregateVerify(&sig, keys.data(), keys.size(), encoder.buf(), encoder.size());
}

bool
Verifier::verifyKeyLocator(const MultiPartyKeyLocator& locator, const MultipartySchema& schema)
{
    std::set<int> verified;
    std::set<int> optionalVerified;
    for (const auto& signer: locator.getLocators()) {
        if (signer.getType() != tlv::Name) return false;
        for (int i = 0; i < schema.signers.size(); i ++) {
            if (verified.count(i) != 0) continue;
            if (schema.signers.at(i).match(signer.getName())) {
                verified.emplace(i);
            }
        }
        for (int i = 0; i < schema.optionalSigners.size(); i ++) {
            if (verified.count(i) != 0) continue;
            if (schema.optionalSigners.at(i).match(signer.getName())) {
                verified.emplace(i);
            }
        }
    }
    return verified.size() == schema.signers.size() && optionalVerified.size() >= schema.minOptionalSigners;
}

Initiator::Initiator()
{
    bls_library_init();
}

} // namespace ndn