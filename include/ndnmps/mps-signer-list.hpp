//
// Created by Tyler on 12/29/20.
//

#ifndef NDNMPS_MPS_SIGNER_LIST_HPP
#define NDNMPS_MPS_SIGNER_LIST_HPP

#include "ndnmps/common.hpp"
#include <vector>
#include <ndn-cxx/key-locator.hpp>

namespace ndn {

class MpsSignerList
{
public:
    class Error : public tlv::Error
    {
    public:
        using tlv::Error::Error;
    };
public: // constructors
    /** \brief Construct an empty list.
     *  \post `empty() == true`
     */
    MpsSignerList();

    /** \brief Construct from vector of names.
     *  \note Implicit conversion is permitted.
     *  \post `getType() == tlv::Name`
     */
    MpsSignerList(std::vector<Name>  signers);

    /** \brief Construct from wire encoding.
     */
    explicit
    MpsSignerList(const Block& wire);

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

    const std::vector<Name>&
    getSigners() const;

    void
    setSigners(const std::vector<Name>& locators);

    std::vector<Name>&
    getMutableSigners();

private:
    std::vector<Name> m_locators;
    mutable Block m_wire;
};

} // namespace ndn

#endif //NDNMPS_MPS_SIGNER_LIST_HPP
