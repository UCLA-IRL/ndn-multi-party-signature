#include <ndn-cxx/data.hpp>
#include <ndnmps/multi-party-key-locator.hpp>
#include "ndnmps/multi-party-signature.hpp"

namespace ndn {

MultiPartySignature::MultiPartySignature(/* args */)
{
}

MultiPartySignature::~MultiPartySignature()
{
}

SignatureInfo
MultiPartySignature::getMultiPartySignatureInfo(const std::vector<Name>& keys)
{
    std::vector<KeyLocator> signers(keys.size());
    for (const auto &s : keys) {
        signers.emplace_back(s);
    }
    MultiPartyKeyLocator locator(signers);
    SignatureInfo info(static_cast<tlv::SignatureTypeValue>(tlv::MpsSignatureSha256WithBls));
    info.addCustomTlv(locator.wireEncode());
    return info;
}

} // namespace ndn