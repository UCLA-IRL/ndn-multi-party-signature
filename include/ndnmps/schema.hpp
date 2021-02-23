#ifndef NDNMPS_SCHEMA_HPP
#define NDNMPS_SCHEMA_HPP

#include <ndn-cxx/name.hpp>
#include <set>
#include <list>
#include "mps-signer-list.hpp"
#include "bls-helpers.hpp"

namespace ndn {
namespace mps {

/**
 * A class to store wild card name that can wildcard match other names.
 * We use generic component with string "_" as a wildcard of the component.
 */
class WildCardName : public Name {
public:

  /**
   * The constructor of the wild card name.
   */
  WildCardName() = default;
  WildCardName(const Name& format);
  WildCardName(const std::string& str);
  WildCardName(const char * str);
  WildCardName(const Block& block);

  /**
   * Wildcard match the given name with this WildCardName.
   * @param name the name to be matched
   * @return true if the name can be matched.
   */
  bool
  match(const Name& name) const;
};

/**
 * @brief configuration file to guide signing and verification.
 */
class MultipartySchema {
public:
  WildCardName m_pktName; // Data name
  std::string m_ruleId; // rule ID
  std::vector<WildCardName> m_signers; // required signers, wildcard name
  std::vector<WildCardName> m_optionalSigners; // optional signers, wildcard name
  size_t m_minOptionalSigners; // min required optional signers

public:
  /**
   * Decode the schema from the JSON.
   * @param fileOrConfigStr the file name or the json to be decoded.
   * @return the schema decoded.
   * @throw if the given string cannot be decoded (invalid format).
   */
  static MultipartySchema
  fromJSON(const std::string& fileOrConfigStr);

  /**
   * Decode the schema from the INFO.
   * @param fileOrConfigStr the file name or the json to be decoded.
   * @return the schema decoded.
   * @throw if the given string cannot be decoded (invalid format).
   */
  static MultipartySchema
  fromINFO(const std::string& fileOrConfigStr);

  /**
   * The default constructor for the schema.
   */
  MultipartySchema();

  bool
  match(const Name& packetName) const {
    return m_pktName.match(packetName);
  }

  /**
   * Encode the schema to (INFO) string.
   * @return the corresponding INFO string.
   */
  std::string
  toString();

  /**
   * verify if this signer list can satisfy this schema.
   * @param locator the signer list containing all signer party
   * @return true if the locator satisifies this schema
   */
  bool
  passSchema(const MpsSignerList& signers) const;
};

class MultipartySchemaContainer
{
public:
  std::list<MultipartySchema> m_schemas;
  std::map<Name, BLSPublicKey> m_trustedIds; // keyName, keyBits

public:
  void
  loadTrustedIds(const std::string& fileOrConfigStr);

  bool
  passSchema(const Name& packetName, const MpsSignerList& signers) const;

  /**
   * the the minimum possible signer set from the available signing party
   * so the aggregater may be able to reduce the length of signer list
   * @return the minimum set of signer that can satisfy this schema
   */
  MpsSignerList
  getAvailableSigners(const MultipartySchema& schema) const;

  /**
   * @brief When a signer is unavailable. find a replacement.
   * @param signers The existing list and will be renewed.
   * @param unavailableKey The key name of the unavailable signer.
   * @param schema The schema.
   * @return nonempty MpsSignerList and a diff name list if there is an available replacement of the unavailable key.
   */
  std::tuple<MpsSignerList, std::vector<Name>>
  replaceSigner(const MpsSignerList& signers, const Name& unavailableKey, const MultipartySchema& schema) const;

  BLSPublicKey
  aggregateKey(const MpsSignerList& signers) const;

private:
  /**
   * @brief Try get a matched key from the truste IDs
   * @param pattern The wildcard name of the target key name.
   * @return a name vector if exists. Empty vector if not exists.
   */
  std::vector<Name>
  getMatchedKeys(const WildCardName& pattern) const;
};

}  // namespace mps
}  // namespace ndn

#endif  // NDNMPS_SCHEMA_HPP