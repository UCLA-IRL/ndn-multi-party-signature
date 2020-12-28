#include <ndn-cxx/signature.hpp>

namespace ndn {

class MultiPartySignature
{
private:
    SignatureInfo m_info;
    mutable Block m_value;
public:
  MultiPartySignature(/* args */);
  ~MultiPartySignature();
};

} // namespace ndn