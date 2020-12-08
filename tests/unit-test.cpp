#include <iostream>
#include "ndnmps/multi-party-signature.hpp"
#include "schema.hpp"

namespace ndn {

void
testSchema()
{
  std::string configStr = R"({
    "pi": 3.141,
    "happy": true,
    "name": "Niels",
    "nothing": null,
    "answer": {
      "everything": 42
    },
    "list": [1, 0, 2],
    "object": {
      "currency": "USD",
      "value": 42.99
    }
  })";
  auto schema = MultipartySchema::fromString(configStr);
  std::cout << schema.toString() << std::endl;
}

}  // namespace ndn

int
main(int argc, char const *argv[])
{
  ndn::testSchema();
  return 0;
}
