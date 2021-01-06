#include "ndnmps/players.hpp"

namespace ndn {

Signer::Signer(MpsSigner mpsSigner)
            : m_mpsSigner(mpsSigner)
{
}

const MpsSigner&
Signer::getMpsSigner() const
{
    return m_mpsSigner;
}

MpsSigner&
Signer::getMpsSigner()
{
    return m_mpsSigner;
}

Verifier::Verifier(MpsVerifier verifier)
        : m_verifier(verifier)
{
}

const MpsVerifier&
Verifier::getMpsVerifier() const
{
    return m_verifier;
}

MpsVerifier&
Verifier::getMpsVerifier()
{
    return m_verifier;
}

} // namespace ndn