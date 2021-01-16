/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2013-2020, Regents of the University of California.
 *
 * This file, originally written as part of ndncert, a certificate management system based on NDN,
 * is a part of ndnmps, a NDN multi signature library.
 *
 * See AUTHORS.md for complete list of ndnmps authors and contributors.
 */

#include "ndnmps/players.hpp"
#include "test-common.hpp"
#include <ndn-cxx/util/dummy-client-face.hpp>

namespace ndn {
namespace ndnmps {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestPlayers, IdentityManagementTimeFixture)

BOOST_AUTO_TEST_CASE(VerifierFetch)
{
  util::DummyClientFace face(io, m_keyChain, {true, true});
  Verifier verifier(MpsVerifier(), face);
  verifier.setCertVerifyCallback([](auto&){return true;});

  MpsSigner signer("/a/b/c/KEY/1234");
  BOOST_CHECK_EQUAL(signer.getSignerKeyName(), "/a/b/c/KEY/1234");
  auto pub = signer.getPublicKey();

  //certificate
  security::Certificate cert;
  cert.setName(Name(signer.getSignerKeyName())
        .append("self").appendVersion(5678));
  BufferPtr ptr = make_shared<Buffer>(blsGetSerializedPublicKeyByteSize());
  BOOST_ASSERT(blsPublicKeySerialize(ptr->data(), ptr->size(), &pub) != 0);
  cert.setContent(ptr);
  cert.setFreshnessPeriod(time::seconds(1000));
  signer.sign(cert);
  BOOST_ASSERT(signer.getSignerKeyName().isPrefixOf(cert.getName()));


  //data to test
  auto data1 = make_shared<Data>();
  data1->setName(Name("/a/b/c/d"));
  data1->setContent(makeNestedBlock(tlv::Content, Name("/1/2/3/4")));

  MultipartySchema schema;
  schema.signers.emplace_back(WildCardName(signer.getSignerKeyName()));

  signer.sign(*data1);

  bool received = false;
  face.onSendInterest.connect([&](const Interest& interest){
    BOOST_CHECK_EQUAL(interest.getName(), signer.getSignerKeyName());
    BOOST_CHECK_EQUAL(interest.getCanBePrefix(), true);
    received = true;
  });

  bool finish = false;
  bool output = false;
  verifier.asyncVerifySignature(data1, make_shared<MultipartySchema>(schema),
          [&](bool input){finish = true; output = input;});

  BOOST_CHECK_EQUAL(finish, false);
  advanceClocks(time::milliseconds(20), 10);
  BOOST_CHECK_EQUAL(received, true);
  BOOST_CHECK_EQUAL(finish, false);
  face.receive(cert);
  advanceClocks(time::milliseconds(20), 10);
  BOOST_CHECK_EQUAL(finish, true);
  BOOST_CHECK_EQUAL(output, true);
}

BOOST_AUTO_TEST_CASE(VerifierFetchTimeout)
{
  util::DummyClientFace face(io, m_keyChain, {true, true});
  Verifier verifier(MpsVerifier(), face);
  verifier.setCertVerifyCallback([](auto&){return true;});

  MpsSigner signer("/a/b/c/KEY/1234");
  BOOST_CHECK_EQUAL(signer.getSignerKeyName(), "/a/b/c/KEY/1234");

  //data to test
  auto data1 = make_shared<Data>();
  data1->setName(Name("/a/b/c/d"));
  data1->setContent(makeNestedBlock(tlv::Content, Name("/1/2/3/4")));

  MultipartySchema schema;
  schema.signers.emplace_back(WildCardName(signer.getSignerKeyName()));

  signer.sign(*data1);

  bool received = false;
  face.onSendInterest.connect([&](const Interest& interest){
    BOOST_CHECK_EQUAL(interest.getName(), signer.getSignerKeyName());
    BOOST_CHECK_EQUAL(interest.getCanBePrefix(), true);
    received = true;
  });

  bool finish = false;
  bool output = false;
  verifier.asyncVerifySignature(data1, make_shared<MultipartySchema>(schema),
                                [&](bool input){finish = true; output = input;});

  BOOST_CHECK_EQUAL(finish, false);
  advanceClocks(time::milliseconds(200), 40);
  BOOST_CHECK_EQUAL(finish, true);
  BOOST_CHECK_EQUAL(output, false);
}

BOOST_AUTO_TEST_CASE(VerifierListFetch)
{
  util::DummyClientFace face(io, m_keyChain, {true, true});
  Verifier verifier(MpsVerifier(), face);
  verifier.setCertVerifyCallback([](auto&){return true;});

  MpsSigner signer("/a/b/c");
  BOOST_CHECK_EQUAL(signer.getSignerKeyName(), "/a/b/c");
  auto pub = signer.getPublicKey();

  MpsSigner signer2("/a/b/d");
  auto pub2 = signer2.getPublicKey();

  verifier.addCert("/a/b/c", pub);
  verifier.addCert("/a/b/d", pub2);

  shared_ptr<Data> data1 = make_shared<Data>();
  data1->setName(Name("/a/b/c/d"));
  data1->setContent(makeNestedBlock(tlv::Content, Name("/1/2/3/4")));

  MultipartySchema schema;
  schema.signers.emplace_back(WildCardName(signer.getSignerKeyName()));
  schema.signers.emplace_back(WildCardName(signer2.getSignerKeyName()));

  //add signer list
  SignatureInfo info(static_cast<tlv::SignatureTypeValue>(tlv::SignatureSha256WithBls), KeyLocator("/some/signer/list"));
  data1->setSignatureInfo(info);
  MpsSignerList list;
  list.emplace_back(signer.getSignerKeyName());
  list.emplace_back(signer2.getSignerKeyName());
  Data signerList;
  signerList.setName("/some/signer/list");
  signerList.setFreshnessPeriod(time::seconds(1000));
  signerList.setContent(makeNestedBlock(tlv::Content, list));
  m_keyChain.sign(signerList, signingWithSha256());

  //sign
  auto sig1 = signer.getSignature(*data1);
  auto sig2 = signer2.getSignature(*data1);

  MpsAggregater aggregater;
  std::vector<blsSignature> signatures;
  {
    blsSignature sig1s;
    BOOST_ASSERT(blsSignatureDeserialize(&sig1s, sig1.value(), sig1.value_size()));
    signatures.emplace_back(sig1s);
  }
  {
    blsSignature sig2s;
    BOOST_ASSERT(blsSignatureDeserialize(&sig2s, sig2.value(), sig2.value_size()));
    signatures.emplace_back(sig2s);
  }
  aggregater.buildMultiSignature(*data1, signatures);

  bool received = false;
  face.onSendInterest.connect([&](const Interest& interest){
    BOOST_CHECK_EQUAL(interest.getName(), "/some/signer/list");
    BOOST_CHECK_EQUAL(interest.getCanBePrefix(), true);
    received = true;
  });

  bool finish = false;
  bool output = false;
  verifier.asyncVerifySignature(data1, make_shared<MultipartySchema>(schema),
                                [&](bool input){finish = true; output = input;});

  BOOST_CHECK_EQUAL(finish, false);
  advanceClocks(time::milliseconds(20), 10);
  BOOST_CHECK_EQUAL(received, true);
  BOOST_CHECK_EQUAL(finish, false);
  face.receive(signerList);
  advanceClocks(time::milliseconds(20), 10);
  BOOST_CHECK_EQUAL(finish, true);
  BOOST_CHECK_EQUAL(output, true);
}


//TODO get schema with key(multiple round)

BOOST_AUTO_TEST_SUITE_END()  // TestMpsSignerList

} // namespace tests
} // namespace ndnmps
} // namespace ndn


