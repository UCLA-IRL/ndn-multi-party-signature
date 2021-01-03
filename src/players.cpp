#include <set>
#include "ndnmps/players.hpp"
#include "ndnmps/common.hpp"
#include "ndnmps/multi-party-signature.hpp"

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
    std::vector<uint8_t> outputBuf(blsGetSerializedPublicKeyByteSize());
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
    if (sigInfo.getSignatureType() != tlv::MpsSignatureSha256WithBls) {
        NDN_THROW(std::runtime_error("Signer got non-BLS signature type"));
    }

    data.setSignatureInfo(sigInfo);

    EncodingBuffer encoder;
    data.wireEncode(encoder, true);

    blsSignature sig;
    blsSign(&sig, &m_sk, encoder.buf(), encoder.size());
    auto signatureBuf = make_shared<Buffer>(blsGetSerializedSignatureByteSize());
    auto written_size = blsSignatureSerialize(signatureBuf->data(), signatureBuf->size(), &sig);
    if (written_size == 0) {
        NDN_THROW(std::runtime_error("Error on serializing signature"));
    }
    signatureBuf->resize(written_size);
    return Block(tlv::SignatureValue, signatureBuf);
}

void
Signer::sign(Data& data, const Name& keyName)
{
    SignatureInfo info(static_cast<tlv::SignatureTypeValue>(tlv::MpsSignatureSha256WithBls), KeyLocator(keyName));
    auto signature = getSignature(data, info);

    data.setSignatureInfo(info);
    data.setSignatureValue(signature.getBuffer());
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
    MultiPartyKeyLocator locator;
    if (locatorBlock) {
        locator.wireDecode(*locatorBlock);
    } else {
        if (sigInfo.getKeyLocator().getType() == tlv::Name)
            locator.getMutableLocators().emplace_back(sigInfo.getKeyLocator().getName());
    }
    if (!MultipartySchema::verifyKeyLocator(locator, schema)) return false;

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

    auto signedRanges = data.extractSignedRanges();
    if (signedRanges.size() == 1) { // to avoid copying in current ndn-cxx impl
        const auto& it = signedRanges.begin();
        return blsFastAggregateVerify(&sig, keys.data(), keys.size(), it->first, it->second);
    } else {
        EncodingBuffer encoder;
        for (const auto &it : signedRanges) {
            encoder.appendByteArray(it.first, it.second);
        }
        return blsFastAggregateVerify(&sig, keys.data(), keys.size(), encoder.buf(), encoder.size());
    }
}

bool
Verifier::verifySignaturePiece(Data data, const SignatureInfo& sigInfo, const Name& signedBy, const Block& signaturePiece) {
    if (sigInfo.getSignatureType() != tlv::MpsSignatureSha256WithBls) {
        NDN_THROW(std::runtime_error("Signer got non-BLS signature type"));
    }

    data.setSignatureInfo(sigInfo);

    blsPublicKey publicKey = m_certs.at(signedBy);
    blsSignature sig;
    if (blsSignatureDeserialize(&sig, signaturePiece.value(), signaturePiece.value_size()) == 0) return false;

    auto signedRanges = data.extractSignedRanges();
    if (signedRanges.size() == 1) { // to avoid copying in current ndn-cxx impl
        const auto& it = signedRanges.begin();
        return blsVerify(&sig, &publicKey, it->first, it->second);
    } else {
        EncodingBuffer encoder;
        for (const auto &it : signedRanges) {
            encoder.appendByteArray(it.first, it.second);
        }
        return blsVerify(&sig, &publicKey, encoder.buf(), encoder.size());
    }
}

Initiator::Initiator()
{
    bls_library_init();
}

void
Initiator::buildMultiSignature(Data& data, const SignatureInfo& sigInfo, const std::vector<blsSignature>& collectedPiece)
{

    data.setSignatureInfo(sigInfo);

    EncodingBuffer encoder;
    data.wireEncode(encoder, true);

    blsSignature outputSig;
    blsAggregateSignature(&outputSig, collectedPiece.data(), collectedPiece.size());
    auto sigBuffer = make_shared<Buffer>(blsGetSerializedSignatureByteSize());
    auto writtenSize = blsSignatureSerialize(sigBuffer->data(), sigBuffer->size(), &outputSig);
    if (writtenSize == 0) {
        NDN_THROW(std::runtime_error("Error on serializing"));
    }
    sigBuffer->resize(writtenSize);

    Block sigValue(tlv::SignatureValue,sigBuffer);

    data.wireEncode(encoder, sigValue);
}

optional<SignatureInfo>
Initiator::getMinMPSignatureInfo(const MultipartySchema& schema, const std::vector<Name>& availableSingerKeys)
{
    auto result = MultipartySchema::getMinPossibleSignerInfo(schema, availableSingerKeys);
    if (!result) return nullopt;
    else return MultiPartySignature::getMultiPartySignatureInfo(*result);
}

} // namespace ndn