#include "ndnmps/schema.hpp"
#include <fstream>
#include <sstream>

namespace ndn {

MultipartySchema
MultipartySchema::fromFile(const std::string& configFile)
{
  MultipartySchema schema;
  std::ifstream config(configFile);
  std::stringstream buffer;
  buffer << config.rdbuf();
  return MultipartySchema::fromString(buffer.str());
}

MultipartySchema
MultipartySchema::fromString(const std::string& configStr)
{
  MultipartySchema schema;
  schema.content = Json::parse(configStr);
  return schema;
}

std::string
MultipartySchema::toString()
{
  return content.dump();
}

} // namespace ndn