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
  //std::cout << schema.toString() << std::endl;
  BOOST_CHECK_EQUAL(schema.prefix, "/example/data");
  BOOST_CHECK_EQUAL(schema.ruleId, "rule1");
  BOOST_CHECK_EQUAL(schema.minOptionalSigners, 2);
  BOOST_CHECK_EQUAL(schema.signers.size(), 2);
  BOOST_CHECK_EQUAL(schema.optionalSigners.size(), 3);
  BOOST_CHECK_EQUAL(schema.signers[0], WildCardName("/example/a/KEY/_/_"));
  BOOST_CHECK_EQUAL(schema.signers[1], WildCardName("/example/b/KEY/_/_"));
  BOOST_CHECK_EQUAL(schema.optionalSigners[0], WildCardName("/example/c/KEY/_/_"));
  BOOST_CHECK_EQUAL(schema.optionalSigners[1], WildCardName("/example/d/KEY/_/_"));
  BOOST_CHECK_EQUAL(schema.optionalSigners[2], WildCardName("/example/e/KEY/_/_"));
}

BOOST_AUTO_TEST_CASE(SchemaInfoINFO)
{
  auto schema = MultipartySchema::fromINFO("tests/unit-tests/config-files/sample-schema.info");
  //std::cout << schema.toString() << std::endl;
  BOOST_CHECK_EQUAL(schema.prefix, "/example/data");
  BOOST_CHECK_EQUAL(schema.ruleId, "rule1");
  BOOST_CHECK_EQUAL(schema.minOptionalSigners, 2);
  BOOST_CHECK_EQUAL(schema.signers.size(), 2);
  BOOST_CHECK_EQUAL(schema.optionalSigners.size(), 3);
  BOOST_CHECK_EQUAL(schema.signers[0], WildCardName("/example/a/KEY/_/_"));
  BOOST_CHECK_EQUAL(schema.signers[1], WildCardName("/example/b/KEY/_/_"));
  BOOST_CHECK_EQUAL(schema.optionalSigners[0], WildCardName("/example/c/KEY/_/_"));
  BOOST_CHECK_EQUAL(schema.optionalSigners[1], WildCardName("/example/d/KEY/_/_"));
  BOOST_CHECK_EQUAL(schema.optionalSigners[2], WildCardName("/example/e/KEY/_/_"));
}

BOOST_AUTO_TEST_CASE(SchemaLoadFail)
{
  BOOST_CHECK_THROW(MultipartySchema::fromINFO("tests/unit-tests/config-files/nonexistent.info"), std::exception);
  BOOST_CHECK_THROW(MultipartySchema::fromJSON("tests/unit-tests/config-files/nonexistent.json"), std::exception);
}

BOOST_AUTO_TEST_CASE(SchemaWrite)
{
  MultipartySchema schema;
  schema.prefix = "/a/b/c";
  schema.ruleId = "...";
  schema.signers.emplace_back("/some/key-a");
  schema.signers.emplace_back("/some/key-b");
  schema.optionalSigners.emplace_back("/some/key-c");
  schema.optionalSigners.emplace_back("/some/key-d");
  schema.minOptionalSigners = 1;

  auto schema2 = MultipartySchema::fromINFO(schema.toString());

  BOOST_CHECK_EQUAL(schema.prefix, schema2.prefix);
  BOOST_CHECK_EQUAL(schema.ruleId, schema2.ruleId);
  BOOST_CHECK_EQUAL_COLLECTIONS(schema.signers.begin(), schema.signers.end(),
                                schema2.signers.begin(), schema2.signers.end());
  BOOST_CHECK_EQUAL_COLLECTIONS(schema.optionalSigners.begin(), schema.optionalSigners.end(),
                                schema2.optionalSigners.begin(), schema2.optionalSigners.end());
  BOOST_CHECK_EQUAL(schema.minOptionalSigners, schema2.minOptionalSigners);
}

BOOST_AUTO_TEST_CASE(SchemaWrite2)
{
  MultipartySchema schema;
  schema.prefix = "/a/b/c";
  schema.ruleId = "...";
  schema.signers.emplace_back("/some/key-a");
  schema.signers.emplace_back("/some/key-b");

  auto schema2 = MultipartySchema::fromINFO(schema.toString());

  BOOST_CHECK_EQUAL(schema.prefix, schema2.prefix);
  BOOST_CHECK_EQUAL(schema.ruleId, schema2.ruleId);
  BOOST_CHECK_EQUAL_COLLECTIONS(schema.signers.begin(), schema.signers.end(),
                                schema2.signers.begin(), schema2.signers.end());
  BOOST_CHECK_EQUAL_COLLECTIONS(schema.optionalSigners.begin(), schema.optionalSigners.end(),
                                schema2.optionalSigners.begin(), schema2.optionalSigners.end());
  BOOST_CHECK_EQUAL(schema.minOptionalSigners, schema2.minOptionalSigners);
}

BOOST_AUTO_TEST_CASE(SchemaWrite3)
{
  MultipartySchema schema;
  schema.prefix = "/a/b/c";
  schema.ruleId = "...";
  schema.optionalSigners.emplace_back("/some/key-c");
  schema.optionalSigners.emplace_back("/some/key-d");
  schema.minOptionalSigners = 1;

  auto schema2 = MultipartySchema::fromINFO(schema.toString());

  BOOST_CHECK_EQUAL(schema.prefix, schema2.prefix);
  BOOST_CHECK_EQUAL(schema.ruleId, schema2.ruleId);
  BOOST_CHECK_EQUAL_COLLECTIONS(schema.signers.begin(), schema.signers.end(),
                                schema2.signers.begin(), schema2.signers.end());
  BOOST_CHECK_EQUAL_COLLECTIONS(schema.optionalSigners.begin(), schema.optionalSigners.end(),
                                schema2.optionalSigners.begin(), schema2.optionalSigners.end());
  BOOST_CHECK_EQUAL(schema.minOptionalSigners, schema2.minOptionalSigners);
}

BOOST_AUTO_TEST_SUITE_END()  // TestSchema

} // namespace tests
} // namespace ndnmps
} // namespace ndn
