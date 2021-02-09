#include "ndnmps/mps-signer-list.hpp"

#include <utility>

namespace ndn {
namespace mps {

MpsSignerList::MpsSignerList(std::vector<Name>&& signers)
    : m_signers(std::move(signers))
{
}

MpsSignerList::MpsSignerList(const std::vector<Name>& signers)
    : m_signers(signers)
{
}

MpsSignerList::MpsSignerList(const Block& wire)
{
  wireDecode(wire);
}

Block
MpsSignerList::wireEncode() const
{
  auto wire = Block(tlv::MpsSignerList);
  for (const auto& item : m_signers) {
    wire.push_back(item.wireEncode());
  }
  wire.encode();
  return wire;
}

template <encoding::Tag TAG>
size_t
MpsSignerList::wireEncode(EncodingImpl<TAG>& encoder) const
{
  auto b = wireEncode();
  encoder.appendBlock(b);
  return b.size();
}

NDN_CXX_DEFINE_WIRE_ENCODE_INSTANTIATIONS(MpsSignerList);

void
MpsSignerList::wireDecode(const Block& wire)
{
  if (wire.type() != tlv::MpsSignerList) {
    NDN_THROW(ndn::tlv::Error("MultiPartySignerList", wire.type()));
  }
  wire.parse();
  m_signers.clear();
  for (const auto& item : wire.elements()) {
    m_signers.emplace_back(item);
  }
}

std::ostream&
operator<<(std::ostream& os, const MpsSignerList& signerList)
{
  os << "MpsSignerList [ ";
  for (const auto& i : signerList.m_signers) {
    os << i << ", ";
  }
  return os << "]";
}

}  // namespace mps
}  // namespace ndn