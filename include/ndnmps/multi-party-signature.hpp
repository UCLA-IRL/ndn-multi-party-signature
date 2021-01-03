#ifndef NDNMPS_MULTI_PARTY_SIGNATURE
#define NDNMPS_MULTI_PARTY_SIGNATURE

#include <ndn-cxx/signature.hpp>

namespace ndn {

class MultiPartySignature
{
private:
public:
  MultiPartySignature(/* args */);
  ~MultiPartySignature();

public:
    static SignatureInfo
    getMultiPartySignatureInfo(const std::vector<Name>& keys);
};

} // namespace ndn

#endif // NDNMPS_MULTI_PARTY_SIGNATURE