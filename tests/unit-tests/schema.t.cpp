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
  auto schema = MultipartySchema::fromINFO("../tests/unit-tests/config-files/sample-schema.info");
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
  BOOST_CHECK_THROW(MultipartySchema::fromINFO("../tests/unit-tests/config-files/nonexistent.info"), std::exception);
  BOOST_CHECK_THROW(MultipartySchema::fromJSON("../tests/unit-tests/config-files/nonexistent.json"), std::exception);
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

BOOST_AUTO_TEST_CASE(SchemaKeyMatches)
{
  MultipartySchema schema;
  schema.prefix = "/a/b/c";
  schema.ruleId = "...";
  schema.signers.emplace_back("/a/_");

  BOOST_CHECK(schema.getKeyMatches("/a/b").size() == 1);
  BOOST_CHECK(schema.getKeyMatches("/a").empty());
  BOOST_CHECK(schema.getKeyMatches("/a/b/c").empty());
  schema.signers.emplace_back("/_/b");
  BOOST_CHECK(schema.getKeyMatches("/a/b").size() == 2);
  BOOST_CHECK(schema.getKeyMatches("/c").empty());
}

BOOST_AUTO_TEST_CASE(SchemaMinSigner)
{
  MultipartySchema schema;
  schema.prefix = "/a/b/c";
  schema.ruleId = "...";
  schema.signers.emplace_back("/a");
  schema.signers.emplace_back("/b");

  std::vector<Name> names;

  BOOST_CHECK(schema.getMinSigners(names).empty());
  names.emplace_back("/a");
  BOOST_CHECK(schema.getMinSigners(names).empty());
  names.emplace_back("/b");
  BOOST_CHECK(schema.getMinSigners(names) == std::set<Name>(names.begin(), names.end()));

  schema.optionalSigners.emplace_back("/c");
  schema.optionalSigners.emplace_back("/d");
  schema.optionalSigners.emplace_back("/e");
  schema.minOptionalSigners = 2;

  BOOST_CHECK(schema.getMinSigners(names).empty());
  names.emplace_back("/c");
  BOOST_CHECK(schema.getMinSigners(names).empty());
  names.emplace_back("/e");
  BOOST_CHECK(schema.getMinSigners(names) == std::set<Name>(names.begin(), names.end()));
  names.emplace_back("/e");
  BOOST_CHECK(schema.getMinSigners(names).size() == 4);
  names.emplace_back("/d");
  BOOST_CHECK(schema.getMinSigners(names).size() == 4);
}

BOOST_AUTO_TEST_CASE(SchemaMinSignerMultipleMatchName)
{
  MultipartySchema schema;
  schema.prefix = "/a/b/c";
  schema.ruleId = "...";
  schema.signers.emplace_back("/a");
  schema.signers.emplace_back("/b/_");
  schema.optionalSigners.emplace_back("/_/c");
  schema.minOptionalSigners = 1;

  std::vector<Name> names;

  BOOST_CHECK(schema.getMinSigners(names).empty());
  names.emplace_back("/a");
  BOOST_CHECK(schema.getMinSigners(names).empty());
  names.emplace_back("/b/c");
  BOOST_CHECK(schema.getMinSigners(names) == std::set<Name>(names.begin(), names.end()));
}

BOOST_AUTO_TEST_CASE(SchemaMinSignerMultipleMatchPosition)
{
  MultipartySchema schema;
  schema.prefix = "/a/b/c";
  schema.ruleId = "...";
  schema.signers.emplace_back("/a/_");
  schema.optionalSigners.emplace_back("/b/_");
  schema.minOptionalSigners = 1;

  std::vector<Name> names;

  BOOST_CHECK(schema.getMinSigners(names).empty());
  names.emplace_back("/a/b");
  BOOST_CHECK(schema.getMinSigners(names).empty());
  names.emplace_back("/a/c");
  BOOST_CHECK(schema.getMinSigners(names).empty());
  names.emplace_back("b/c");
  BOOST_CHECK(schema.getMinSigners(names).size() == 2);
}

BOOST_AUTO_TEST_SUITE_END()  // TestSchema

}  // namespace tests
}  // namespace mps
}  // namespace ndn
