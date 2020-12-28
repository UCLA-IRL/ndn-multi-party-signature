//
// Created by Tyler on 12/29/20.
//

#include "ndnmps/multi-party-key-locator.hpp"

#include <utility>

namespace ndn {
MultiPartyKeyLocator::MultiPartyKeyLocator()
        : m_locators()
{
}

MultiPartyKeyLocator::MultiPartyKeyLocator(const std::vector<KeyLocator>& signers)
        : m_locators(signers)
{
}


MultiPartyKeyLocator::MultiPartyKeyLocator(const Block& wire)
        : m_locators()
{
    wireDecode(wire);
}

template<encoding::Tag TAG>
size_t
MultiPartyKeyLocator::wireEncode(EncodingImpl<TAG>& encoder) const
{
    // MultiPartyKeyLocator = MULTI-PARTY-KEY-LOCATOR-TYPE TLV-LENGTH *KeyLocator

    size_t totalLength = 0;

    for (const auto& s : m_locators) {
        totalLength += s.wireEncode(encoder);
    }

    totalLength += encoder.prependVarNumber(totalLength);
    totalLength += encoder.prependVarNumber(tlv::MultiPartyKeyLocator);
    return totalLength;
}

NDN_CXX_DEFINE_WIRE_ENCODE_INSTANTIATIONS(MultiPartyKeyLocator);

const Block&
MultiPartyKeyLocator::wireEncode() const
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
MultiPartyKeyLocator::wireDecode(const Block& wire)
{
    if (wire.type() != tlv::MultiPartyKeyLocator)
        NDN_THROW(Error("MultiPartyKeyLocator", wire.type()));

    m_locators.clear();
    m_wire = wire;
    m_wire.parse();

    for (const auto& e : m_wire.elements()) {
        m_locators.emplace_back(KeyLocator(e));
    }
}

const std::vector<KeyLocator>&
MultiPartyKeyLocator::getLocators() const
{
    return m_locators;
}

void
MultiPartyKeyLocator::setLocators(const std::vector<KeyLocator>& locators)
{
    m_locators = locators;
    m_wire.reset();
}

std::vector<KeyLocator>&
MultiPartyKeyLocator::getMutableLocators(){
    m_wire.reset();
    return m_locators;
}
}