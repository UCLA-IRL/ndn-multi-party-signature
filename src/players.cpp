#include "ndnmps/players.hpp"

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

Verifier::Verifier()
{
    bls_library_init();
}

Initiator::Initiator()
{
    bls_library_init();
}

} // namespace ndn