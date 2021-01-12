#include "ndnmps/multi-party-signature.hpp"

#include <ndn-cxx/data.hpp>
#include <ndnmps/mps-signer-list.hpp>

namespace ndn {

MultiPartySignature::MultiPartySignature(/* args */)
{
}

MultiPartySignature::~MultiPartySignature()
{
}

SignatureInfo
MultiPartySignature::getMultiPartySignatureInfo(const std::set<Name>& keys)
{
  MpsSignerList locator(keys);
  SignatureInfo info(static_cast<tlv::SignatureTypeValue>(tlv::SignatureSha256WithBls));
  info.addCustomTlv(locator.wireEncode());
  return info;
}

}  // namespace ndn