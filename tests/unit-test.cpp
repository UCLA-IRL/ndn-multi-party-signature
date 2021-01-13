#include <iostream>
#include "ndnmps/multi-party-signature.hpp"
#include "ndnmps/schema.hpp"

namespace ndn {

void
testSchema()
{
  auto schema = MultipartySchema::fromINFO("../sample-schema.info");
  std::cout << schema.toString() << std::endl;
  auto schema2 = MultipartySchema::fromJSON("../sample-schema.json");
  std::cout << schema.toString() << std::endl;
}

}  // namespace ndn

int
main(int argc, char const *argv[])
{
  ndn::testSchema();
  return 0;
}