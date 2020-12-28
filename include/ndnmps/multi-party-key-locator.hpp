//
// Created by Tyler on 12/29/20.
//

#ifndef NDNMPS_MULTI_PARTY_KEY_LOCATOR_HPP
#define NDNMPS_MULTI_PARTY_KEY_LOCATOR_HPP

#include "ndnmps/common.hpp"
#include <vector>
#include <ndn-cxx/key-locator.hpp>

namespace ndn {

class MultiPartyKeyLocator
{
public:
    class Error : public tlv::Error
    {
    public:
        using tlv::Error::Error;
    };
public: // constructors
    /** \brief Construct an empty KeyLocator.
     *  \post `empty() == true`
     */
    MultiPartyKeyLocator();

    /** \brief Construct from vector of names.
     *  \note Implicit conversion is permitted.
     *  \post `getType() == tlv::Name`
     */
    MultiPartyKeyLocator(const std::vector<KeyLocator>& signers);

    /** \brief Construct from wire encoding.
     */
    explicit
    MultiPartyKeyLocator(const Block& wire);

public: // encode and decode
    /** \brief Prepend wire encoding to \p encoder.
     */
    template<encoding::Tag TAG>
    size_t
    wireEncode(EncodingImpl<TAG>& encoder) const;

    const Block&
    wireEncode() const;

    /** \brief Decode from wire encoding.
     *  \throw Error outer TLV type is not KeyLocator
     *  \note No error is raised for an unrecognized nested TLV, but attempting to reencode will throw.
     */
    void
    wireDecode(const Block& wire);

    const std::vector<KeyLocator>&
    getLocators() const;

    void
    setLocators(const std::vector<KeyLocator>& locators);

    std::vector<KeyLocator>&
    getMutableLocators();

private:
    std::vector<KeyLocator> m_locators;
    mutable Block m_wire;
};

} // namespace ndn

#endif //NDNMPS_MULTI_PARTY_KEY_LOCATOR_HPP
