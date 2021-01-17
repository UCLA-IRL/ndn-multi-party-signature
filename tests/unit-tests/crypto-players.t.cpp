/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2013-2020, Regents of the University of California.
 *
 * This file, originally written as part of ndncert, a certificate management system based on NDN,
 * is a part of ndnmps, a NDN multi signature library.
 *
 * See AUTHORS.md for complete list of ndnmps authors and contributors.
 */

#include "ndnmps/crypto-players.hpp"
#include "test-common.hpp"

namespace ndn {
namespace ndnmps {
namespace tests {

BOOST_AUTO_TEST_SUITE(TestCryptoPlayers)

BOOST_AUTO_TEST_CASE(TestSignerPublicKey)
{
  MpsSigner signer("/a/b/c");
  BOOST_CHECK_EQUAL(signer.getSignerKeyName(), "/a/b/c");
  auto pub = signer.getPublicKey();
  auto pubStr = signer.getpublicKeyStr();
  blsPublicKey pub2;
  BOOST_ASSERT( blsPublicKeyDeserialize(&pub2, pubStr.data(), pubStr.size())!= 0);
  BOOST_ASSERT(blsPublicKeyIsEqual(&pub, &pub2));
}

BOOST_AUTO_TEST_CASE(TestSignerVerifier)
{
  MpsSigner signer("/a/b/c");
  BOOST_CHECK_EQUAL(signer.getSignerKeyName(), WildCardName("/a/b/c"));
  auto pub = signer.getPublicKey();

  MpsVerifier verifier;
  verifier.addCert("/a/b/c", pub);

  Data data1;
  data1.setName(Name("/a/b/c/d"));
  data1.setContent(makeNestedBlock(tlv::Content, Name("/1/2/3/4")));

  MultipartySchema schema;
  schema.signers.emplace_back(WildCardName(signer.getSignerKeyName()));

  signer.sign(data1);
  BOOST_CHECK(verifier.verifySignature(data1, schema));
  BOOST_CHECK_EQUAL(data1.getSignatureValue().value_size(), blsGetSerializedSignatureByteSize());
}

BOOST_AUTO_TEST_CASE(TestSignerVerifierBadKey)
{
  MpsSigner signer("/a/b/c");
  BOOST_CHECK_EQUAL(signer.getSignerKeyName(), WildCardName("/a/b/c"));
  auto pub = signer.getPublicKey();

  MpsVerifier verifier;
  verifier.addCert("/a/b/c", pub);

  Data data1;
  data1.setName(Name("/a/b/c/d"));
  data1.setContent(makeNestedBlock(tlv::Content, Name("/1/2/3/4")));

  MultipartySchema schema;
  schema.signers.emplace_back(WildCardName("/q/w/e/r"));

  signer.sign(data1);
  BOOST_ASSERT(!verifier.verifySignature(data1, schema));
}

BOOST_AUTO_TEST_CASE(TestSignerVerifierBadSig)
{
  MpsSigner signer("/a/b/c");
  BOOST_CHECK_EQUAL(signer.getSignerKeyName(), WildCardName("/a/b/c"));
  auto pub = signer.getPublicKey();

  MpsVerifier verifier;
  verifier.addCert("/a/b/c", pub);

  Data data1;
  data1.setName(Name("/a/b/c/d"));
  data1.setContent(makeNestedBlock(tlv::Content, Name("/1/2/3/4")));

  MultipartySchema schema;
  schema.signers.emplace_back(WildCardName(WildCardName(signer.getSignerKeyName())));

  signer.sign(data1);
  data1.setContent(makeNestedBlock(tlv::Content, Name("/1/2/3/4/5"))); //changed content
  BOOST_ASSERT(!verifier.verifySignature(data1, schema));
}

BOOST_AUTO_TEST_CASE(TestAggregateSignVerify)
{
  MpsSigner signer("/a/b/c");
  BOOST_CHECK_EQUAL(signer.getSignerKeyName(), WildCardName("/a/b/c"));
  auto pub = signer.getPublicKey();

  MpsSigner signer2("/a/b/d");
  auto pub2 = signer2.getPublicKey();

  MpsVerifier verifier;
  verifier.addCert("/a/b/c", pub);
  verifier.addCert("/a/b/d", pub2);

  Data data1;
  data1.setName(Name("/a/b/c/d"));
  data1.setContent(makeNestedBlock(tlv::Content, Name("/1/2/3/4")));

  MultipartySchema schema;
  schema.signers.emplace_back(WildCardName(signer.getSignerKeyName()));
  schema.signers.emplace_back(WildCardName(signer2.getSignerKeyName()));

  //add signer list
  SignatureInfo info(static_cast<tlv::SignatureTypeValue>(tlv::SignatureSha256WithBls), KeyLocator("/some/signer/list"));
  data1.setSignatureInfo(info);
  MpsSignerList list;
  list.emplace_back(signer.getSignerKeyName());
  list.emplace_back(signer2.getSignerKeyName());
  verifier.addSignerList("/some/signer/list", list);

  //sign
  auto sig1 = signer.getSignature(data1);
  auto sig2 = signer2.getSignature(data1);
  BOOST_ASSERT(verifier.verifySignaturePiece(data1, signer.getSignerKeyName(), sig1));
  BOOST_ASSERT(verifier.verifySignaturePiece(data1, signer2.getSignerKeyName(), sig2));

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
  aggregater.buildMultiSignature(data1, signatures);
  BOOST_ASSERT(verifier.verifySignature(data1, schema));
}

BOOST_AUTO_TEST_CASE(TestAggregateSignVerifyBadKey)
{
  MpsSigner signer("/a/b/c");
  BOOST_CHECK_EQUAL(signer.getSignerKeyName(), WildCardName("/a/b/c"));
  auto pub = signer.getPublicKey();

  MpsSigner signer2("/a/b/d");
  auto pub2 = signer2.getPublicKey();

  MpsVerifier verifier;
  verifier.addCert("/a/b/c", pub);
  verifier.addCert("/a/b/d", pub2);

  Data data1;
  data1.setName(Name("/a/b/c/d"));
  data1.setContent(makeNestedBlock(tlv::Content, Name("/1/2/3/4")));

  MultipartySchema schema;
  schema.signers.emplace_back(WildCardName(signer.getSignerKeyName()));
  schema.signers.emplace_back(WildCardName(signer2.getSignerKeyName()));

  //add signer list
  SignatureInfo info(static_cast<tlv::SignatureTypeValue>(tlv::SignatureSha256WithBls), KeyLocator("/some/signer/list"));
  data1.setSignatureInfo(info);
  MpsSignerList list;
  list.emplace_back(signer.getSignerKeyName());
  list.emplace_back(signer.getSignerKeyName()); //wrong!
  verifier.addSignerList("/some/signer/list", list);

  //sign
  auto sig1 = signer.getSignature(data1);
  auto sig2 = signer2.getSignature(data1);
  BOOST_ASSERT(verifier.verifySignaturePiece(data1, signer.getSignerKeyName(), sig1));
  BOOST_ASSERT(verifier.verifySignaturePiece(data1, signer2.getSignerKeyName(), sig2));

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
  aggregater.buildMultiSignature(data1, signatures);
  BOOST_ASSERT(!verifier.verifySignature(data1, schema));
}

BOOST_AUTO_TEST_CASE(TestAggregateSignVerifyBadSig)
{
  MpsSigner signer("/a/b/c");
  BOOST_CHECK_EQUAL(signer.getSignerKeyName(), WildCardName("/a/b/c"));
  auto pub = signer.getPublicKey();

  MpsSigner signer2("/a/b/d");
  auto pub2 = signer2.getPublicKey();

  MpsVerifier verifier;
  verifier.addCert("/a/b/c", pub);
  verifier.addCert("/a/b/d", pub2);

  Data data1;
  data1.setName(Name("/a/b/c/d"));
  data1.setContent(makeNestedBlock(tlv::Content, Name("/1/2/3/4")));

  MultipartySchema schema;
  schema.signers.emplace_back(WildCardName(signer.getSignerKeyName()));
  schema.signers.emplace_back(WildCardName(signer2.getSignerKeyName()));

  //add signer list
  SignatureInfo info(static_cast<tlv::SignatureTypeValue>(tlv::SignatureSha256WithBls), KeyLocator("/some/signer/list"));
  data1.setSignatureInfo(info);
  MpsSignerList list;
  list.emplace_back(signer.getSignerKeyName());
  list.emplace_back(signer2.getSignerKeyName());
  verifier.addSignerList("/some/signer/list", list);

  //sign
  auto sig1 = signer.getSignature(data1);
  BOOST_ASSERT(verifier.verifySignaturePiece(data1, signer.getSignerKeyName(), sig1));
  auto sig2 = signer2.getSignature(data1);
  data1.setContent(makeNestedBlock(tlv::Content, Name("/1/2/3/4/5")));
  BOOST_ASSERT(!verifier.verifySignaturePiece(data1, signer2.getSignerKeyName(), sig2));

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
  aggregater.buildMultiSignature(data1, signatures);
  BOOST_ASSERT(!verifier.verifySignature(data1, schema));
}

BOOST_AUTO_TEST_SUITE_END()  // TestCryptoPlayers

} // namespace tests
} // namespace ndnmps
} // namespace ndn
