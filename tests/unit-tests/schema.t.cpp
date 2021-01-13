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

BOOST_AUTO_TEST_SUITE(TestSchema)

BOOST_AUTO_TEST_CASE(SchemaInfoJSON)
{
  auto schema = MultipartySchema::fromJSON("tests/unit-tests/config-files/sample-schema.json");
  std::cout << schema.toString() << std::endl;
  BOOST_CHECK_EQUAL(schema.prefix, "/example/data");
  BOOST_CHECK_EQUAL(schema.ruleId, "rule1");
  BOOST_CHECK_EQUAL(schema.minOptionalSigners, 2);
  BOOST_CHECK_EQUAL(schema.signers.size(), 2);
}

BOOST_AUTO_TEST_CASE(SchemaInfoINFO)
{
  auto schema = MultipartySchema::fromINFO("tests/unit-tests/config-files/sample-schema.info");
  //std::cout << schema.toString() << std::endl;
  BOOST_CHECK_EQUAL(schema.prefix, "/example/data");
  BOOST_CHECK_EQUAL(schema.ruleId, "rule1");
  BOOST_CHECK_EQUAL(schema.minOptionalSigners, 2);
  BOOST_CHECK_EQUAL(schema.signers.size(), 2);
}

BOOST_AUTO_TEST_SUITE_END()  // TestSchema

} // namespace tests
} // namespace ndnmps
} // namespace ndn
