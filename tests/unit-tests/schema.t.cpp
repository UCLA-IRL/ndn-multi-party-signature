#include "ndnmps/schema.hpp"
#include "test-common.hpp"

namespace ndn {
namespace mps {
namespace tests {

BOOST_AUTO_TEST_SUITE(TestSchema)

BOOST_AUTO_TEST_CASE(SchemaInfoJSON)
{
  auto schema = MultipartySchema::fromJSON("../tests/unit-tests/config-files/sample-schema.json");
  BOOST_CHECK_EQUAL(schema.m_pktName.m_name, "/example/data");
  BOOST_CHECK_EQUAL(schema.m_ruleId, "rule1");
  BOOST_CHECK_EQUAL(schema.m_minOptionalSigners, 2);
  BOOST_CHECK_EQUAL(schema.m_signers.size(), 2);
  BOOST_CHECK_EQUAL(schema.m_optionalSigners.size(), 3);
  BOOST_CHECK(schema.m_signers[0].match(Name("/example/a/KEY/1/23")));
  BOOST_CHECK(schema.m_signers[1].match(Name("/example/b/KEY/xx/yy")));
  BOOST_CHECK(schema.m_optionalSigners[0].match(Name("/example/c/KEY/verylongcomponent/short")));
  BOOST_CHECK(schema.m_optionalSigners[1].match(Name("/example/d/KEY/123/456")));
  BOOST_CHECK(schema.m_optionalSigners[2].match(Name("/example/e/KEY/789/0")));
}

BOOST_AUTO_TEST_CASE(SchemaInfoINFO)
{
  auto schema = MultipartySchema::fromINFO("../tests/unit-tests/config-files/sample-schema.info");
  BOOST_CHECK_EQUAL(schema.m_pktName.m_name, "/example/data");
  BOOST_CHECK_EQUAL(schema.m_ruleId, "rule1");
  BOOST_CHECK_EQUAL(schema.m_minOptionalSigners, 2);
  BOOST_CHECK_EQUAL(schema.m_signers.size(), 2);
  BOOST_CHECK_EQUAL(schema.m_optionalSigners.size(), 3);
  BOOST_CHECK(schema.m_signers[0].match(Name("/example/a/KEY/1/23")));
  BOOST_CHECK(schema.m_signers[1].match(Name("/example/b/KEY/xx/yy")));
  BOOST_CHECK(schema.m_optionalSigners[0].match(Name("/example/c/KEY/verylongcomponent/short")));
  BOOST_CHECK(schema.m_optionalSigners[1].match(Name("/example/d/KEY/123/456")));
  BOOST_CHECK(schema.m_optionalSigners[2].match(Name("/example/e/KEY/789/0")));
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

BOOST_AUTO_TEST_CASE(SchemaVerify)
{
  MultipartySchema schema;
  schema.m_pktName.m_name = Name("/a/b/c");
  schema.m_ruleId = "...";
  schema.m_signers.emplace_back("/a");
  schema.m_signers.emplace_back("/b");

  BOOST_CHECK_EQUAL(schema.m_signers[0].m_name, Name("/a"));
  BOOST_CHECK_EQUAL(schema.m_signers[1].m_name, Name("/b"));
  BOOST_CHECK_EQUAL(schema.m_signers[0].m_times, 1);
  BOOST_CHECK_EQUAL(schema.m_signers[1].m_times, 1);

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
  schema.m_signers.emplace_back("/b/*");
  schema.m_optionalSigners.emplace_back("/*/c");
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
  schema.m_signers.emplace_back("/a/*");
  schema.m_optionalSigners.emplace_back("/b/*");
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

BOOST_AUTO_TEST_CASE(SchemaMinSignerWithPrefix)
{
  MultipartySchema schema;
  schema.m_pktName.m_name = Name("/a/b/c");
  schema.m_ruleId = "...";
  schema.m_signers.emplace_back("2x/a/*");
  schema.m_optionalSigners.emplace_back("3x/b/*");
  schema.m_minOptionalSigners = 2;

  std::vector<Name> names;
  names.emplace_back("/a/b");
  names.emplace_back("/b/c");
  BOOST_CHECK(!schema.passSchema(names));
  names.emplace_back("/a/c");
  names.emplace_back("/b/d");
  BOOST_CHECK(schema.passSchema(names));
}

BOOST_AUTO_TEST_SUITE_END()  // TestSchema

}  // namespace tests
}  // namespace mps
}  // namespace ndn