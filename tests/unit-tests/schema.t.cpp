#include "ndnmps/schema.hpp"
#include "test-common.hpp"

namespace ndn {
namespace mps {
namespace tests {

BOOST_AUTO_TEST_SUITE(TestSchema)

BOOST_AUTO_TEST_CASE(SchemaInfoJSON)
{
  auto schema = MultipartySchema::fromJSON("../tests/unit-tests/config-files/sample-schema.json");
  //std::cout << schema.toString() << std::endl;
  BOOST_CHECK_EQUAL(schema.m_pktName.m_name, "/example/data");
  BOOST_CHECK_EQUAL(schema.m_ruleId, "rule1");
  BOOST_CHECK_EQUAL(schema.m_minOptionalSigners, 2);
  BOOST_CHECK_EQUAL(schema.m_signers.size(), 2);
  BOOST_CHECK_EQUAL(schema.m_optionalSigners.size(), 3);
  BOOST_CHECK_EQUAL(schema.m_signers[0].m_name, Name("/example/a/KEY/_/_"));
  BOOST_CHECK_EQUAL(schema.m_signers[1].m_name, Name("/example/b/KEY/_/_"));
  BOOST_CHECK_EQUAL(schema.m_optionalSigners[0].m_name, Name("/example/c/KEY/_/_"));
  BOOST_CHECK_EQUAL(schema.m_optionalSigners[1].m_name, Name("/example/d/KEY/_/_"));
  BOOST_CHECK_EQUAL(schema.m_optionalSigners[2].m_name, Name("/example/e/KEY/_/_"));
}

BOOST_AUTO_TEST_CASE(SchemaInfoINFO)
{
  auto schema = MultipartySchema::fromINFO("../tests/unit-tests/config-files/sample-schema.info");
  //std::cout << schema.toString() << std::endl;
  BOOST_CHECK_EQUAL(schema.m_pktName.m_name, "/example/data");
  BOOST_CHECK_EQUAL(schema.m_ruleId, "rule1");
  BOOST_CHECK_EQUAL(schema.m_minOptionalSigners, 2);
  BOOST_CHECK_EQUAL(schema.m_signers.size(), 2);
  BOOST_CHECK_EQUAL(schema.m_optionalSigners.size(), 3);
  BOOST_CHECK_EQUAL(schema.m_signers[0].m_name, Name("/example/a/KEY/_/_"));
  BOOST_CHECK_EQUAL(schema.m_signers[1].m_name, Name("/example/b/KEY/_/_"));
  BOOST_CHECK_EQUAL(schema.m_optionalSigners[0].m_name, Name("/example/c/KEY/_/_"));
  BOOST_CHECK_EQUAL(schema.m_optionalSigners[1].m_name, Name("/example/d/KEY/_/_"));
  BOOST_CHECK_EQUAL(schema.m_optionalSigners[2].m_name, Name("/example/e/KEY/_/_"));
}

BOOST_AUTO_TEST_CASE(SchemaLoadFail)
{
  BOOST_CHECK_THROW(MultipartySchema::fromINFO("../tests/unit-tests/config-files/nonexistent.info"), std::exception);
  BOOST_CHECK_THROW(MultipartySchema::fromJSON("../tests/unit-tests/config-files/nonexistent.json"), std::exception);
}

BOOST_AUTO_TEST_CASE(SchemaWrite)
{
  MultipartySchema schema;
  schema.m_pktName.m_name = Name("/a/b/c");
  schema.m_ruleId = "...";
  schema.m_signers.emplace_back("/some/key-a");
  schema.m_signers.emplace_back("/some/key-b");
  schema.m_optionalSigners.emplace_back("/some/key-c");
  schema.m_optionalSigners.emplace_back("/some/key-d");
  schema.m_minOptionalSigners = 1;

  auto schema2 = MultipartySchema::fromINFO(schema.toString());

  BOOST_CHECK_EQUAL(schema.m_pktName.m_name, schema2.m_pktName.m_name);
  BOOST_CHECK_EQUAL(schema.m_ruleId, schema2.m_ruleId);
  BOOST_CHECK_EQUAL(schema.m_signers.size(), schema2.m_signers.size());
  BOOST_CHECK_EQUAL(schema.m_optionalSigners.size(), schema2.m_optionalSigners.size());
  BOOST_CHECK_EQUAL(schema.m_minOptionalSigners, schema2.m_minOptionalSigners);
}

BOOST_AUTO_TEST_CASE(SchemaWrite2)
{
  MultipartySchema schema;
  schema.m_pktName.m_name = Name("/a/b/c");
  schema.m_ruleId = "...";
  schema.m_signers.emplace_back("/some/key-a");
  schema.m_signers.emplace_back("/some/key-b");

  auto schema2 = MultipartySchema::fromINFO(schema.toString());

  BOOST_CHECK_EQUAL(schema.m_pktName.m_name, schema2.m_pktName.m_name);
  BOOST_CHECK_EQUAL(schema.m_ruleId, schema2.m_ruleId);
  BOOST_CHECK_EQUAL(schema.m_signers.size(), schema2.m_signers.size());
  BOOST_CHECK_EQUAL(schema.m_optionalSigners.size(), schema2.m_optionalSigners.size());
  BOOST_CHECK_EQUAL(schema.m_minOptionalSigners, schema2.m_minOptionalSigners);
}

BOOST_AUTO_TEST_CASE(SchemaWrite3)
{
  MultipartySchema schema;
  schema.m_pktName.m_name = Name("/a/b/c");
  schema.m_ruleId = "...";
  schema.m_optionalSigners.emplace_back("/some/key-c");
  schema.m_optionalSigners.emplace_back("/some/key-d");
  schema.m_minOptionalSigners = 1;

  auto schema2 = MultipartySchema::fromINFO(schema.toString());

  BOOST_CHECK_EQUAL(schema.m_pktName.m_name, schema2.m_pktName.m_name);
  BOOST_CHECK_EQUAL(schema.m_ruleId, schema2.m_ruleId);
  BOOST_CHECK_EQUAL(schema.m_signers.size(), schema2.m_signers.size());
  BOOST_CHECK_EQUAL(schema.m_optionalSigners.size(), schema2.m_optionalSigners.size());
  BOOST_CHECK_EQUAL(schema.m_minOptionalSigners, schema2.m_minOptionalSigners);
}

BOOST_AUTO_TEST_CASE(SchemaMinSigner)
{
  MultipartySchema schema;
  schema.m_pktName.m_name = Name("/a/b/c");
  schema.m_ruleId = "...";
  schema.m_signers.emplace_back("/a");
  schema.m_signers.emplace_back("/b");

  std::vector<Name> names;

  BOOST_CHECK(!schema.passSchema(names));
  names.emplace_back("/a");
  BOOST_CHECK(!schema.passSchema(names));
  names.emplace_back("/b");
  BOOST_CHECK(schema.passSchema(names));

  schema.m_optionalSigners.emplace_back("/c");
  schema.m_optionalSigners.emplace_back("/d");
  schema.m_optionalSigners.emplace_back("/e");
  schema.m_minOptionalSigners = 2;

  BOOST_CHECK(!schema.passSchema(names));
  names.emplace_back("/c");
  BOOST_CHECK(!schema.passSchema(names));
  names.emplace_back("/e");
  BOOST_CHECK(schema.passSchema(names));
  names.emplace_back("/e");
  BOOST_CHECK(schema.passSchema(names));
  names.emplace_back("/d");
  BOOST_CHECK(schema.passSchema(names));
}

BOOST_AUTO_TEST_CASE(SchemaMinSignerMultipleMatchName)
{
  MultipartySchema schema;
  schema.m_pktName.m_name = Name("/a/b/c");
  schema.m_ruleId = "...";
  schema.m_signers.emplace_back("/a");
  schema.m_signers.emplace_back("/b/_");
  schema.m_optionalSigners.emplace_back("/_/c");
  schema.m_minOptionalSigners = 1;

  std::vector<Name> names;

  BOOST_CHECK(!schema.passSchema(names));
  names.emplace_back("/a");
  BOOST_CHECK(!schema.passSchema(names));
  names.emplace_back("/b/c");
  BOOST_CHECK(schema.passSchema(names));
}

BOOST_AUTO_TEST_CASE(SchemaMinSignerMultipleMatchPosition)
{
  MultipartySchema schema;
  schema.m_pktName.m_name = Name("/a/b/c");
  schema.m_ruleId = "...";
  schema.m_signers.emplace_back("/a/_");
  schema.m_optionalSigners.emplace_back("/b/_");
  schema.m_minOptionalSigners = 1;

  std::vector<Name> names;
  BOOST_CHECK(!schema.passSchema(names));
  names.emplace_back("/a/b");
  BOOST_CHECK(!schema.passSchema(names));
  names.emplace_back("/a/c");
  BOOST_CHECK(!schema.passSchema(names));
  names.emplace_back("/b/c");
  BOOST_CHECK(schema.passSchema(names));
}

BOOST_AUTO_TEST_SUITE_END()  // TestSchema

}  // namespace tests
}  // namespace mps
}  // namespace ndn