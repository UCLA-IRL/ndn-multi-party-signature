/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2013-2020, Regents of the University of California.
 *
 * This file, originally written as part of ndncert, a certificate management system based on NDN,
 * is a part of ndnmps, a NDN multi signature library.
 *
 * See AUTHORS.md for complete list of ndnmps authors and contributors.
 */

#include "ndnmps/schema.hpp"
#include "test-common.hpp"

namespace ndn {
namespace ndnmps {
namespace tests {

BOOST_AUTO_TEST_SUITE(TestMpsSignerList)

BOOST_AUTO_TEST_CASE(EmptyList)
{
  MpsSignerList a;
  BOOST_CHECK_EQUAL(a.m_signers.empty(), true);

  Block wire = a.wireEncode();
  // These octets are obtained from the snippet below.
  // This check is intended to detect unexpected encoding change in the future.
  // for (auto it = wire.begin(); it != wire.end(); ++it) {
  //   printf("0x%02x, ", *it);
  // }
  static const uint8_t expected[] = {
          tlv::MpsSignerList, 0x00
  };
  BOOST_CHECK_EQUAL_COLLECTIONS(expected, expected + sizeof(expected),
                                wire.begin(), wire.end());

  MpsSignerList b(wire);
  BOOST_CHECK_EQUAL(a, b);
  BOOST_CHECK_EQUAL(a.m_signers.empty(), true);
}

BOOST_AUTO_TEST_CASE(Encoding)
{
  std::set<Name> names;
  names.emplace("/A");
  MpsSignerList a(names);

  const Block& wire = a.wireEncode();
  // These octets are obtained from the snippet below.
  // This check is intended to detect unexpected encoding change in the future.
  // for (auto it = wire.begin(); it != wire.end(); ++it) {
  //   printf("0x%02x, ", *it);
  // }
  static const uint8_t expected[] = {
          tlv::MpsSignerList, 0x05,
            tlv::Name, 0x03, tlv::GenericNameComponent, 0x01, 'A'
  };
  BOOST_CHECK_EQUAL_COLLECTIONS(expected, expected + sizeof(expected),
                                wire.begin(), wire.end());

  MpsSignerList b(wire);
  BOOST_CHECK_EQUAL(a, b);
  BOOST_CHECK_EQUAL_COLLECTIONS(b.m_signers.begin(), b.m_signers.end(), names.begin(), names.end());
}

BOOST_AUTO_TEST_CASE(Encoding2)
{
  std::set<Name> names;
  names.emplace("/A");
  names.emplace("/b");
  names.emplace("/C");
  MpsSignerList a(names);

  const Block& wire = a.wireEncode();

  MpsSignerList b(wire);
  BOOST_CHECK_EQUAL(a, b);
  BOOST_CHECK_EQUAL_COLLECTIONS(b.m_signers.begin(), b.m_signers.end(), names.begin(), names.end());
}

BOOST_AUTO_TEST_CASE(Equality)
{
  MpsSignerList a;
  MpsSignerList b;
  BOOST_CHECK_EQUAL(a == b, true);
  BOOST_CHECK_EQUAL(a != b, false);

  a.m_signers.emplace("/A");
  BOOST_CHECK_EQUAL(a == b, false);
  BOOST_CHECK_EQUAL(a != b, true);

  b.m_signers.emplace("/B");
  BOOST_CHECK_EQUAL(a == b, false);
  BOOST_CHECK_EQUAL(a != b, true);

  b.m_signers.emplace("/A");
  a.m_signers.emplace("/B");
  BOOST_CHECK_EQUAL(a == b, true);
  BOOST_CHECK_EQUAL(a != b, false);
}

BOOST_AUTO_TEST_SUITE_END()  // TestMpsSignerList

} // namespace tests
} // namespace ndnmps
} // namespace ndn


