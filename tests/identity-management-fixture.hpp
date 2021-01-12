/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2013-2020, Regents of the University of California.
 *
 * This file, originally written as part of NFD (Named Data Networking Forwarding Daemon),
 * is a part of ndnmps, a NDN multi signature library.
 *
 * See AUTHORS.md for complete list of ndnmps authors and contributors.
 */

#ifndef NDN_TESTS_IDENTITY_MANAGEMENT_FIXTURE_HPP
#define NDN_TESTS_IDENTITY_MANAGEMENT_FIXTURE_HPP

#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <vector>

namespace ndn {
namespace ndnmps {
namespace tests {

class IdentityManagementBaseFixture
{
public:
  ~IdentityManagementBaseFixture();

  bool
  saveCertToFile(const Data& obj, const std::string& filename);

protected:
  std::set<Name> m_identities;
  std::set<std::string> m_certFiles;
};

/**
 * @brief A test suite level fixture to help with identity management
 *
 * Test cases in the suite can use this fixture to create identities.  Identities,
 * certificates, and saved certificates are automatically removed during test teardown.
 */
class IdentityManagementFixture : public IdentityManagementBaseFixture
{
public:
  IdentityManagementFixture();

  /**
   * @brief Add identity @p identityName
   * @return name of the created self-signed certificate
   */
  security::Identity
  addIdentity(const Name& identityName,
              const KeyParams& params = security::KeyChain::getDefaultKeyParams());

  /**
   *  @brief Save identity certificate to a file
   *  @param identity identity
   *  @param filename file name, should be writable
   *  @return whether successful
   */
  bool
  saveCertificate(const security::Identity& identity, const std::string& filename);

  /**
   * @brief Issue a certificate for \p subIdentityName signed by \p issuer
   *
   *  If identity does not exist, it is created.
   *  A new key is generated as the default key for identity.
   *  A default certificate for the key is signed by the issuer using its default certificate.
   *
   *  @return the sub identity
   */
  security::Identity
  addSubCertificate(const Name& subIdentityName, const security::Identity& issuer,
                    const KeyParams& params = security::KeyChain::getDefaultKeyParams());

  /**
   * @brief Add a self-signed certificate to @p key with issuer ID @p issuer
   */
  security::Certificate
  addCertificate(const security::Key& key, const std::string& issuer);

protected:
  KeyChain m_keyChain;
};

} // namespace tests
} // namespace ndnmps
} // namespace ndn

#endif // NDN_TESTS_IDENTITY_MANAGEMENT_FIXTURE_HPP
