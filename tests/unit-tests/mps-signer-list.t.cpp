#include "ndnmps/schema.hpp"
#include "test-common.hpp"

namespace ndn {
namespace mps {
namespace tests {

BOOST_AUTO_TEST_SUITE(TestMpsSignerList)

BOOST_AUTO_TEST_CASE(EmptyList)
{
  MpsSignerList a;
  BOOST_CHECK(a.m_signers.empty());

  Block wire = a.wireEncode();
  // These octets are obtained from the snippet below.
  // This check is intended to detect unexpected encoding change in the future.
  // for (auto it = wire.begin(); it != wire.end(); ++it) {
  //   printf("0x%02x, ", *it);
  // }
  static const uint8_t expected[] = {
      tlv::MpsSignerList, 0x00};
  BOOST_CHECK_EQUAL_COLLECTIONS(expected, expected + sizeof(expected),
                                wire.begin(), wire.end());

  MpsSignerList b(wire);
  BOOST_CHECK(a.m_signers == b.m_signers);
  BOOST_CHECK(a.m_signers.empty());
}

BOOST_AUTO_TEST_CASE(Encoding)
{
  MpsSignerList a;
  a.m_signers.emplace_back("/A");

  const Block& wire = a.wireEncode();
  // These octets are obtained from the snippet below.
  // This check is intended to detect unexpected encoding change in the future.
  // for (auto it = wire.begin(); it != wire.end(); ++it) {
  //   printf("0x%02x, ", *it);
  // }
  static const uint8_t expected[] = {
      tlv::MpsSignerList, 0x05,
      ndn::tlv::Name, 0x03, ndn::tlv::GenericNameComponent, 0x01, 'A'};
  BOOST_CHECK_EQUAL_COLLECTIONS(expected, expected + sizeof(expected),
                                wire.begin(), wire.end());

  MpsSignerList b(wire);
  BOOST_CHECK(a.m_signers == b.m_signers);

  b = a;
  BOOST_CHECK(a.m_signers == b.m_signers);
}

BOOST_AUTO_TEST_CASE(Encoding2)
{
  MpsSignerList a;
  a.m_signers.emplace_back("/A");
  a.m_signers.emplace_back("/b");
  a.m_signers.emplace_back("/C");

  const Block& wire = a.wireEncode();

  MpsSignerList b(wire);
  BOOST_CHECK(a.m_signers == b.m_signers);
}

BOOST_AUTO_TEST_CASE(Equality)
{
  MpsSignerList a;
  MpsSignerList b;
  BOOST_CHECK_EQUAL(a == b, true);
  BOOST_CHECK_EQUAL(a != b, false);

  a.m_signers.emplace_back("/A");
  BOOST_CHECK_EQUAL(a == b, false);
  BOOST_CHECK_EQUAL(a != b, true);

  b.m_signers.emplace_back("/B");
  BOOST_CHECK_EQUAL(a == b, false);
  BOOST_CHECK_EQUAL(a != b, true);

  b.m_signers.emplace_back("/A");
  a.m_signers.emplace_back("/B");
  BOOST_CHECK_EQUAL(a == b, true);
  BOOST_CHECK_EQUAL(a != b, false);
}

BOOST_AUTO_TEST_SUITE_END()  // TestMpsSignerList

}  // namespace tests
}  // namespace mps
}  // namespace ndn
