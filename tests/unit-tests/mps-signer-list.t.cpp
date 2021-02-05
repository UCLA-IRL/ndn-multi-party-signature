#include "ndnmps/schema.hpp"
#include "test-common.hpp"

namespace ndn {
namespace mps {
namespace tests {

BOOST_AUTO_TEST_SUITE(TestMpsSignerList)

BOOST_AUTO_TEST_CASE(EmptyList)
{
  MpsSignerList a;
  BOOST_CHECK_EQUAL(a.empty(), true);

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
  BOOST_CHECK_EQUAL(a, b);
  BOOST_CHECK_EQUAL(a.empty(), true);
}

BOOST_AUTO_TEST_CASE(Encoding)
{
  MpsSignerList a;
  a.emplace_back("/A");

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
  BOOST_CHECK_EQUAL(a, b);

  b = a;
  BOOST_CHECK_EQUAL(a, b);
}

BOOST_AUTO_TEST_CASE(Encoding2)
{
  MpsSignerList a;
  a.emplace_back("/A");
  a.emplace_back("/b");
  a.emplace_back("/C");

  const Block& wire = a.wireEncode();

  MpsSignerList b(wire);
  BOOST_CHECK_EQUAL(a, b);
}

BOOST_AUTO_TEST_CASE(Equality)
{
  MpsSignerList a;
  MpsSignerList b;
  BOOST_CHECK_EQUAL(a == b, true);
  BOOST_CHECK_EQUAL(a != b, false);

  a.emplace_back("/A");
  BOOST_CHECK_EQUAL(a == b, false);
  BOOST_CHECK_EQUAL(a != b, true);

  b.emplace_back("/B");
  BOOST_CHECK_EQUAL(a == b, false);
  BOOST_CHECK_EQUAL(a != b, true);

  b.emplace_back("/A");
  a.emplace_back("/B");
  BOOST_CHECK_EQUAL(a == b, true);
  BOOST_CHECK_EQUAL(a != b, false);
}

BOOST_AUTO_TEST_SUITE_END()  // TestMpsSignerList

}  // namespace tests
}  // namespace mps
}  // namespace ndn
