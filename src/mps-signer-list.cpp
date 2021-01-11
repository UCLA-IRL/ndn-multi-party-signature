//
// Created by Tyler on 12/29/20.
//

#include "ndnmps/mps-signer-list.hpp"

#include <utility>

namespace ndn {
MpsSignerList::MpsSignerList()
    : m_locators()
{
}

MpsSignerList::MpsSignerList(std::vector<Name> signers)
    : m_locators(std::move(signers))
{
}

MpsSignerList::MpsSignerList(const Block& wire)
    : m_locators()
{
  wireDecode(wire);
}

template <encoding::Tag TAG>
size_t
MpsSignerList::wireEncode(EncodingImpl<TAG>& encoder) const
{
  // MultiPartySignerList = MULTI-PARTY-KEY-LOCATOR-TYPE TLV-LENGTH *KeyLocator

  size_t totalLength = 0;

  for (const auto& s : m_locators) {
    totalLength += s.wireEncode(encoder);
  }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::MpsSignerList);
  return totalLength;
}

NDN_CXX_DEFINE_WIRE_ENCODE_INSTANTIATIONS(MpsSignerList);

const Block&
MpsSignerList::wireEncode() const
{
  if (m_wire.hasWire())
    return m_wire;

  EncodingEstimator estimator;
  size_t estimatedSize = wireEncode(estimator);

  EncodingBuffer buffer(estimatedSize, 0);
  wireEncode(buffer);

  m_wire = buffer.block();
  return m_wire;
}

void
MpsSignerList::wireDecode(const Block& wire)
{
  if (wire.type() != tlv::MpsSignerList)
    NDN_THROW(Error("MultiPartySignerList", wire.type()));

  m_locators.clear();
  m_wire = wire;
  m_wire.parse();

  for (const auto& e : m_wire.elements()) {
    m_locators.emplace_back(e);
  }
}

const std::vector<Name>&
MpsSignerList::getSigners() const
{
  return m_locators;
}

void
MpsSignerList::setSigners(const std::vector<Name>& locators)
{
  m_locators = locators;
  m_wire.reset();
}

std::vector<Name>&
MpsSignerList::getSigners()
{
  m_wire.reset();
  return m_locators;
}
}  // namespace ndn