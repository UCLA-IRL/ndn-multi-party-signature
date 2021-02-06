#include <ndn-cxx/util/dummy-client-face.hpp>

#include "ndnmps/players.hpp"
#include "test-common.hpp"

namespace ndn {
namespace mps {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestPlayers, IdentityManagementTimeFixture)

BOOST_AUTO_TEST_CASE(VerifierFetch)
{
  util::DummyClientFace face(io, m_keyChain, {true, true});
  Verifier verifier(std::make_unique<MpsVerifier>(), face, true);
  verifier.setCertVerifyCallback([](auto &) { return true; });

  MpsSigner mpsSigner("/a/b/c/KEY/1234");
  BOOST_CHECK_EQUAL(mpsSigner.getSignerKeyName(), "/a/b/c/KEY/1234");
  auto pub = mpsSigner.getPublicKey();

  //certificate
  security::Certificate cert;
  cert.setName(Name(mpsSigner.getSignerKeyName())
                   .append("self")
                   .appendVersion(5678));
  BufferPtr ptr = make_shared<Buffer>(blsGetSerializedPublicKeyByteSize());
  BOOST_ASSERT(blsPublicKeySerialize(ptr->data(), ptr->size(), &pub) != 0);
  cert.setContent(ptr);
  cert.setFreshnessPeriod(time::seconds(1000));
  mpsSigner.sign(cert);
  BOOST_ASSERT(mpsSigner.getSignerKeyName().isPrefixOf(cert.getName()));

  //data to test
  auto data1 = make_shared<Data>();
  data1->setName(Name("/a/b/c/d"));
  data1->setContent(Name("/1/2/3/4").wireEncode());

  MultipartySchema schema;
  schema.signers.emplace_back(WildCardName(mpsSigner.getSignerKeyName()));

  mpsSigner.sign(*data1);

  bool received = false;
  face.onSendInterest.connect([&](const Interest &interest) {
    BOOST_CHECK_EQUAL(interest.getName(), mpsSigner.getSignerKeyName());
    BOOST_CHECK_EQUAL(interest.getCanBePrefix(), true);
    received = true;
  });

  bool finish = false;
  bool output = false;
  advanceClocks(time::milliseconds(20), 10);
  verifier.asyncVerifySignature(data1, make_shared<MultipartySchema>(schema),
                                [&](bool input) {finish = true; output = input; });

  BOOST_CHECK_EQUAL(finish, false);
  advanceClocks(time::milliseconds(20), 10);
  BOOST_CHECK_EQUAL(received, true);
  BOOST_CHECK_EQUAL(finish, false);
  face.receive(cert);
  advanceClocks(time::milliseconds(20), 10);
  BOOST_CHECK_EQUAL(finish, true);
  BOOST_CHECK_EQUAL(output, true);
}

BOOST_AUTO_TEST_CASE(VerifierFetch2)
{
  util::DummyClientFace face(io, m_keyChain, {true, true});
  Verifier verifier(std::make_unique<MpsVerifier>(), face);

  MpsSigner mpsSigner("/a/b/c/KEY/1234");
  BOOST_CHECK_EQUAL(mpsSigner.getSignerKeyName(), "/a/b/c/KEY/1234");
  auto pub = mpsSigner.getPublicKey();
  verifier.m_verifier->addCert(mpsSigner.getSignerKeyName(), pub);

  //data to fetch
  Data dataF;
  dataF.setName(Name("/some/signer/list"));
  std::vector<Name> signers;
  signers.push_back(mpsSigner.getSignerKeyName());
  dataF.setContent(MpsSignerList(signers).wireEncode());
  dataF.setFreshnessPeriod(time::seconds(1));
  m_keyChain.sign(dataF, signingWithSha256());

  //data to test
  auto data1 = make_shared<Data>();
  data1->setName(Name("/a/b/c/d"));
  data1->setContent(Name("/1/2/3/4").wireEncode());

  MultipartySchema schema;
  schema.signers.emplace_back(WildCardName(mpsSigner.getSignerKeyName()));
  mpsSigner.sign(*data1, SignatureInfo(static_cast<ndn::tlv::SignatureTypeValue>(tlv::SignatureSha256WithBls), KeyLocator(dataF.getName())));

  bool received = false;
  face.onSendInterest.connect([&](const Interest &interest) {
    BOOST_CHECK_EQUAL(interest.getName(), dataF.getName());
    BOOST_CHECK_EQUAL(interest.getCanBePrefix(), true);
    received = true;
  });

  bool finish = false;
  bool output = false;
  advanceClocks(time::milliseconds(20), 10);
  verifier.asyncVerifySignature(data1, make_shared<MultipartySchema>(schema),
                                [&](bool input) {finish = true; output = input; });

  BOOST_CHECK_EQUAL(finish, false);
  advanceClocks(time::milliseconds(20), 10);
  BOOST_CHECK_EQUAL(received, true);
  BOOST_CHECK_EQUAL(finish, false);
  face.receive(dataF);
  advanceClocks(time::milliseconds(20), 10);
  BOOST_CHECK_EQUAL(finish, true);
  BOOST_CHECK_EQUAL(output, true);
}

BOOST_AUTO_TEST_CASE(VerifierFetchTimeout)
{
  util::DummyClientFace face(io, m_keyChain, {true, true});
  Verifier verifier(std::make_unique<MpsVerifier>(), face);
  verifier.setCertVerifyCallback([](auto &) { return true; });

  MpsSigner mpsSigner("/a/b/c/KEY/1234");
  BOOST_CHECK_EQUAL(mpsSigner.getSignerKeyName(), "/a/b/c/KEY/1234");

  //data to test
  auto data1 = make_shared<Data>();
  data1->setName(Name("/a/b/c/d"));
  data1->setContent(Name("/1/2/3/4").wireEncode());

  MultipartySchema schema;
  schema.signers.emplace_back(WildCardName(mpsSigner.getSignerKeyName()));

  mpsSigner.sign(*data1);

  bool received = false;
  face.onSendInterest.connect([&](const Interest &interest) {
    BOOST_CHECK_EQUAL(interest.getName(), mpsSigner.getSignerKeyName());
    BOOST_CHECK_EQUAL(interest.getCanBePrefix(), true);
    received = true;
  });

  bool finish = false;
  bool output = false;
  verifier.asyncVerifySignature(data1, make_shared<MultipartySchema>(schema),
                                [&](bool input) {finish = true; output = input; });

  BOOST_CHECK_EQUAL(finish, false);
  advanceClocks(time::milliseconds(200), 40);
  BOOST_CHECK_EQUAL(finish, true);
  BOOST_CHECK_EQUAL(output, false);
}

BOOST_AUTO_TEST_CASE(VerifierListFetch)
{
  util::DummyClientFace face(io, m_keyChain, {true, true});
  Verifier verifier(std::make_unique<MpsVerifier>(), face);
  verifier.setCertVerifyCallback([](auto &) { return true; });

  MpsSigner mpsSigner("/a/b/c");
  BOOST_CHECK_EQUAL(mpsSigner.getSignerKeyName(), "/a/b/c");
  auto pub = mpsSigner.getPublicKey();

  MpsSigner mpsSigner2("/a/b/d");
  auto pub2 = mpsSigner2.getPublicKey();

  verifier.m_verifier->addCert("/a/b/c", pub);
  verifier.m_verifier->addCert("/a/b/d", pub2);

  shared_ptr<Data> data1 = make_shared<Data>();
  data1->setName(Name("/a/b/c/d"));
  data1->setContent(Name("/1/2/3/4").wireEncode());

  MultipartySchema schema;
  schema.signers.emplace_back(WildCardName(mpsSigner.getSignerKeyName()));
  schema.signers.emplace_back(WildCardName(mpsSigner2.getSignerKeyName()));

  //add signer list
  SignatureInfo info(static_cast<ndn::tlv::SignatureTypeValue>(tlv::SignatureSha256WithBls), KeyLocator("/some/signer/list"));
  data1->setSignatureInfo(info);
  MpsSignerList list;
  list.emplace_back(mpsSigner.getSignerKeyName());
  list.emplace_back(mpsSigner2.getSignerKeyName());
  Data signerList;
  signerList.setName("/some/signer/list");
  signerList.setFreshnessPeriod(time::seconds(1000));
  signerList.setContent(list.wireEncode());
  m_keyChain.sign(signerList, signingWithSha256());

  //sign
  auto sig1 = mpsSigner.getSignature(*data1);
  auto sig2 = mpsSigner2.getSignature(*data1);

  MpsAggregator aggregater;
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
  face.onSendInterest.connect([&](const Interest &interest) {
    BOOST_CHECK_EQUAL(interest.getName(), "/some/signer/list");
    BOOST_CHECK_EQUAL(interest.getCanBePrefix(), true);
    received = true;
  });

  bool finish = false;
  bool output = false;
  verifier.asyncVerifySignature(data1, make_shared<MultipartySchema>(schema),
                                [&](bool input) {finish = true; output = input; });

  BOOST_CHECK_EQUAL(finish, false);
  advanceClocks(time::milliseconds(20), 10);
  BOOST_CHECK_EQUAL(received, true);
  BOOST_CHECK_EQUAL(finish, false);
  face.receive(signerList);
  advanceClocks(time::milliseconds(20), 10);
  BOOST_CHECK_EQUAL(finish, true);
  BOOST_CHECK_EQUAL(output, true);
}

BOOST_AUTO_TEST_CASE(VerifierParallelFetch)
{
  util::DummyClientFace face(io, m_keyChain, {true, true});
  Verifier verifier(std::make_unique<MpsVerifier>(), face, true);
  verifier.setCertVerifyCallback([](auto &) { return true; });

  //request1
  MpsSigner mpsSigner("/a/b/c/KEY/1234");
  BOOST_CHECK_EQUAL(mpsSigner.getSignerKeyName(), "/a/b/c/KEY/1234");
  auto pub = mpsSigner.getPublicKey();

  //certificate
  security::Certificate cert;
  cert.setName(Name(mpsSigner.getSignerKeyName())
                   .append("self")
                   .appendVersion(5678));
  BufferPtr ptr = make_shared<Buffer>(blsGetSerializedPublicKeyByteSize());
  BOOST_ASSERT(blsPublicKeySerialize(ptr->data(), ptr->size(), &pub) != 0);
  cert.setContent(ptr);
  cert.setFreshnessPeriod(time::seconds(1000));
  mpsSigner.sign(cert);
  BOOST_ASSERT(mpsSigner.getSignerKeyName().isPrefixOf(cert.getName()));

  //data1 to test
  auto data1 = make_shared<Data>();
  data1->setName(Name("/a/b/c/d"));
  data1->setContent(Name("/1/2/3/4").wireEncode());

  MultipartySchema schema;
  schema.signers.emplace_back(WildCardName(mpsSigner.getSignerKeyName()));

  mpsSigner.sign(*data1);

  auto data2 = make_shared<Data>();
  data2->setName(Name("/a/b/c/d/2"));
  data2->setContent(Name("/1/2/3/4").wireEncode());

  mpsSigner.sign(*data2, "/a/b/NotExist/KEY/1234");

  bool received1 = false;
  bool received2 = false;
  face.onSendInterest.connect([&](const Interest &interest) {
    BOOST_CHECK_EQUAL(interest.getCanBePrefix(), true);
    if (interest.getName().isPrefixOf(cert.getKeyName())) {
      received1 = true;
    }
    else {
      BOOST_CHECK_EQUAL(interest.getName(), "/a/b/NotExist/KEY/1234");
      received2 = true;
    }
  });

  bool finish1 = false;
  bool output1 = false;
  bool finish2 = false;
  bool output2 = false;
  verifier.asyncVerifySignature(data1, make_shared<MultipartySchema>(schema),
                                [&](bool input) {finish1 = true; output1 = input; });
  verifier.asyncVerifySignature(data2, make_shared<MultipartySchema>(schema),
                                [&](bool input) {finish2 = true; output2 = input; });
  BOOST_CHECK_EQUAL(finish1, false);
  BOOST_CHECK_EQUAL(finish2, false);
  advanceClocks(time::milliseconds(20), 10);
  BOOST_CHECK_EQUAL(received1, true);
  BOOST_CHECK_EQUAL(received2, true);
  BOOST_CHECK_EQUAL(finish1, false);
  BOOST_CHECK_EQUAL(finish2, false);
  face.receive(cert);
  advanceClocks(time::milliseconds(20), 10);
  BOOST_CHECK_EQUAL(finish1, true);
  BOOST_CHECK_EQUAL(output1, true);
  BOOST_CHECK_EQUAL(finish2, false);
  BOOST_CHECK_EQUAL(output2, false);
  advanceClocks(time::milliseconds(200), 40);
  BOOST_CHECK_EQUAL(finish2, true);
  BOOST_CHECK_EQUAL(output2, false);
}

BOOST_AUTO_TEST_CASE(SignerFetch)
{
  util::DummyClientFace face(io, m_keyChain, {true, true});
  Signer signer(std::make_unique<MpsSigner>("/a/b/c/KEY/1234"), "/signer", face);
  signer.setDataVerifyCallback([](auto a) { return true; });
  signer.setSignatureVerifyCallback([](auto a) { return true; });

  //data to test
  Data data1;
  data1.setName(Name("/a/b/c/d"));
  data1.setFreshnessPeriod(time::seconds(1000));
  data1.setSignatureInfo(SignatureInfo(static_cast<ndn::tlv::SignatureTypeValue>(tlv::SignatureSha256WithBls),
                                       KeyLocator(signer.m_signer->getSignerKeyName())));
  data1.setSignatureValue(make_shared<Buffer>());
  BOOST_CHECK_NO_THROW(data1.wireEncode());

  //wrapper
  Data wrapper;
  wrapper.setName("/some/mps/wrapper/1234");
  wrapper.setContent(data1.wireEncode());
  wrapper.setFreshnessPeriod(time::seconds(1000));
  m_keyChain.sign(wrapper, signingWithSha256());
  BOOST_CHECK_NO_THROW(Data(wrapper.getContent().blockFromValue()));

  //initiation interest
  Interest signInterest;
  signInterest.setName(Name("/signer/mps/sign"));
  Block appParam(ndn::tlv::ApplicationParameters);
  appParam.push_back(makeNestedBlock(tlv::UnsignedWrapperName, wrapper.getFullName()));
  signInterest.setApplicationParameters(appParam);
  signInterest.setCanBePrefix(false);
  signInterest.setMustBeFresh(true);
  BOOST_ASSERT(signInterest.getName().get(-1).isParametersSha256Digest());

  //result interest
  Interest resultInterest;

  MultipartySchema schema;
  schema.signers.emplace_back(WildCardName(signer.m_signer->getSignerKeyName()));

  bool receivedWrapperFetch = false;
  face.onSendInterest.connect([&](const Interest &interest) {
    if (!Name("/some").isPrefixOf(interest.getName()))
      return;
    BOOST_CHECK_EQUAL(interest.getName(), wrapper.getFullName());
    receivedWrapperFetch = true;
  });

  bool result1_received = false;
  bool result2_received = false;
  bool init_received = false;
  int count = 0;
  face.onSendData.connect([&](const Data &data) {
    BOOST_CHECK(data.getFreshnessPeriod().count() > 0);
    if (Name("/signer/mps/result").isPrefixOf(data.getName())) {
      //result
      BOOST_CHECK_EQUAL(data.getName().size(), 4);
      if (!result1_received) {
        result1_received = true;
        const auto &content = data.getContent();
        content.parse();
        BOOST_CHECK_EQUAL(readString(content.get(tlv::Status)), std::to_string(static_cast<int>(ReplyCode::Processing)));
      }
      else {
        result2_received = true;
        const auto &content = data.getContent();
        content.parse();
        BOOST_CHECK_EQUAL(readString(content.get(tlv::Status)), std::to_string(static_cast<int>(ReplyCode::OK)));
        const auto &v = content.get(ndn::tlv::SignatureValue);
        auto vbuff = make_shared<Buffer>(v.value(), v.value_size());
        data1.setSignatureValue(vbuff);
        MpsVerifier verifier;
        verifier.addCert(signer.m_signer->getSignerKeyName(), signer.m_signer->getPublicKey());
        BOOST_CHECK(verifier.verifySignature(data1, schema));
        BOOST_CHECK_EQUAL(data1.getSignatureValue().value_size(), blsGetSerializedSignatureByteSize());
      }
    }
    else {
      //init
      BOOST_CHECK_EQUAL(data.getName(), signInterest.getName());
      const auto &content = data.getContent();
      content.parse();
      BOOST_CHECK_EQUAL(readString(content.get(tlv::Status)), std::to_string(static_cast<int>(ReplyCode::Processing)));
      resultInterest.setName(Name(content.get(tlv::ResultName).blockFromValue()));
      init_received = true;
    }
  });

  advanceClocks(time::milliseconds(20), 10);
  face.receive(signInterest);
  advanceClocks(time::milliseconds(20), 10);
  BOOST_CHECK_EQUAL(init_received, true);
  BOOST_CHECK_EQUAL(receivedWrapperFetch, true);
  face.receive(resultInterest);
  advanceClocks(time::milliseconds(20), 10);
  BOOST_CHECK_EQUAL(result1_received, true);
  face.receive(wrapper);
  advanceClocks(time::milliseconds(20), 10);
  face.receive(resultInterest);
  advanceClocks(time::milliseconds(20), 10);
  BOOST_CHECK_EQUAL(result2_received, true);
}

BOOST_AUTO_TEST_CASE(SignerFetchTimeout)
{
  util::DummyClientFace face(io, m_keyChain, {true, true});
  Signer signer(std::make_unique<MpsSigner>("/a/b/c/KEY/1234"), "/signer", face);
  signer.setDataVerifyCallback([](auto a) { return true; });
  signer.setSignatureVerifyCallback([](auto a) { return true; });

  //wrapper
  Data wrapper;
  wrapper.setName("/some/mps/wrapper/1234");
  wrapper.setContent(makeEmptyBlock(ndn::tlv::Content));
  wrapper.setFreshnessPeriod(time::seconds(1000));
  m_keyChain.sign(wrapper, signingWithSha256());

  //initiation interest
  Interest signInterest;
  signInterest.setName(Name("/signer/mps/sign"));
  Block appParam(ndn::tlv::ApplicationParameters);
  appParam.push_back(makeNestedBlock(tlv::UnsignedWrapperName, wrapper.getFullName()));
  signInterest.setApplicationParameters(appParam);
  signInterest.setCanBePrefix(false);
  signInterest.setMustBeFresh(true);
  BOOST_ASSERT(signInterest.getName().get(-1).isParametersSha256Digest());

  //result interest
  Interest resultInterest;
  resultInterest.setName(Name("/signer/mps/result-of")
                             .append(signInterest.getName().get(-1).value(), signInterest.getName().get(-1).value_size()));
  resultInterest.setCanBePrefix(true);
  resultInterest.setMustBeFresh(true);

  MultipartySchema schema;
  schema.signers.emplace_back(WildCardName(signer.m_signer->getSignerKeyName()));

  bool receivedWrapperFetch = false;
  face.onSendInterest.connect([&](const Interest &interest) {
    if (!Name("/some").isPrefixOf(interest.getName()))
      return;
    BOOST_CHECK_EQUAL(interest.getName(), wrapper.getFullName());
    receivedWrapperFetch = true;
  });

  bool result1_received = false;
  bool result2_received = false;
  bool init_received = false;
  face.onSendData.connect([&](const Data &data) {
    BOOST_CHECK(data.getFreshnessPeriod().count() > 0);
    if (Name("/signer/mps/result-of").isPrefixOf(data.getName())) {
      //result
      BOOST_CHECK_EQUAL(data.getName().size(), 5);
      BOOST_CHECK(data.getName().get(3).isGeneric());
      BOOST_CHECK_EQUAL_COLLECTIONS(data.getName().get(3).value_begin(), data.getName().get(3).value_end(),
                                    signInterest.getName().get(-1).value_begin(), signInterest.getName().get(-1).value_end());
      if (data.getName().get(-1).toVersion() == 0) {
        result1_received = true;
        const auto &content = data.getContent();
        content.parse();
        BOOST_CHECK_EQUAL(readString(content.get(tlv::Status)), std::to_string(static_cast<int>(ReplyCode::Processing)));
      }
      else {
        result2_received = true;
        const auto &content = data.getContent();
        content.parse();
        BOOST_CHECK_EQUAL(readString(content.get(tlv::Status)), std::to_string(static_cast<int>(ReplyCode::FailedDependency)));
      }
    }
    else {
      //init
      BOOST_CHECK_EQUAL(data.getName(), signInterest.getName());
      const auto &content = data.getContent();
      content.parse();
      BOOST_CHECK_EQUAL(readString(content.get(tlv::Status)), std::to_string(static_cast<int>(ReplyCode::Processing)));
      init_received = true;
    }
  });

  advanceClocks(time::milliseconds(20), 10);
  face.receive(signInterest);
  advanceClocks(time::milliseconds(20), 10);
  BOOST_CHECK_EQUAL(init_received, true);
  BOOST_CHECK_EQUAL(receivedWrapperFetch, true);
  face.receive(resultInterest);
  advanceClocks(time::milliseconds(20), 10);
  BOOST_CHECK_EQUAL(result1_received, true);
  advanceClocks(time::milliseconds(200), 40);
  face.receive(resultInterest);
  advanceClocks(time::milliseconds(20), 10);
  BOOST_CHECK_EQUAL(result2_received, true);
}

BOOST_AUTO_TEST_CASE(SignerFetchNotFound)
{
  util::DummyClientFace face(io, m_keyChain, {true, true});
  Signer signer(std::make_unique<MpsSigner>("/a/b/c/KEY/1234"), "/signer", face);
  signer.setDataVerifyCallback([](auto a) { return true; });
  signer.setSignatureVerifyCallback([](auto a) { return true; });

  //initiation interest
  Interest signInterest;
  signInterest.setName(Name("/signer/mps/sign"));
  Block appParam(ndn::tlv::ApplicationParameters);
  appParam.push_back(makeEmptyBlock(tlv::UnsignedWrapperName));
  signInterest.setApplicationParameters(appParam);
  signInterest.setCanBePrefix(false);
  signInterest.setMustBeFresh(true);
  BOOST_ASSERT(signInterest.getName().get(-1).isParametersSha256Digest());

  //result interest
  Interest resultInterest;
  resultInterest.setName(Name("/signer/mps/result-of")
                             .append(signInterest.getName().get(-1).value(), signInterest.getName().get(-1).value_size()));
  resultInterest.setCanBePrefix(true);
  resultInterest.setMustBeFresh(true);

  MultipartySchema schema;
  schema.signers.emplace_back(WildCardName(signer.m_signer->getSignerKeyName()));

  bool result1_received = false;
  face.onSendData.connect([&](const Data &data) {
    BOOST_CHECK(data.getFreshnessPeriod().count() > 0);
    if (Name("/signer/mps/result-of").isPrefixOf(data.getName())) {
      //result
      BOOST_CHECK_EQUAL(data.getName().size(), 5);
      BOOST_CHECK(data.getName().get(3).isGeneric());
      BOOST_CHECK_EQUAL_COLLECTIONS(data.getName().get(3).value_begin(), data.getName().get(3).value_end(),
                                    signInterest.getName().get(-1).value_begin(),
                                    signInterest.getName().get(-1).value_end());
      result1_received = true;
      const auto &content = data.getContent();
      content.parse();
      BOOST_CHECK_EQUAL(readString(content.get(tlv::Status)), std::to_string(static_cast<int>(ReplyCode::NotFound)));
    }
  });

  advanceClocks(time::milliseconds(20), 10);
  face.receive(resultInterest);
  advanceClocks(time::milliseconds(20), 10);
  BOOST_CHECK_EQUAL(result1_received, true);
}

BOOST_AUTO_TEST_CASE(SignerFetchBadInit)
{
  util::DummyClientFace face(io, m_keyChain, {true, true});
  Signer signer(std::make_unique<MpsSigner>("/a/b/c/KEY/1234"), "/signer", face);
  signer.setDataVerifyCallback([](auto a) { return true; });
  signer.setSignatureVerifyCallback([](auto a) { return true; });

  //data to test
  Data data1;
  data1.setName(Name("/a/b/c/d"));
  data1.setContent(Name("/1/2/3/4").wireEncode());
  data1.setFreshnessPeriod(time::seconds(1000));
  data1.setSignatureInfo(SignatureInfo(static_cast<ndn::tlv::SignatureTypeValue>(tlv::SignatureSha256WithBls),
                                       KeyLocator(signer.m_signer->getSignerKeyName())));
  data1.setSignatureValue(make_shared<Buffer>());
  BOOST_CHECK_NO_THROW(data1.wireEncode());

  //wrapper
  Data wrapper;
  wrapper.setName("/some/mps/wrapper/1234");
  wrapper.setContent(data1.wireEncode());
  wrapper.setFreshnessPeriod(time::seconds(1000));
  m_keyChain.sign(wrapper, signingWithSha256());
  BOOST_CHECK_NO_THROW(Data(wrapper.getContent().blockFromValue()));

  //initiation interest
  Interest signInterest;
  signInterest.setName(Name("/signer/mps/sign"));
  Block appParam(ndn::tlv::ApplicationParameters);
  appParam.push_back(makeNestedBlock(tlv::UnsignedWrapperName, wrapper.getName()));
  signInterest.setApplicationParameters(appParam);
  signInterest.setCanBePrefix(false);
  signInterest.setMustBeFresh(true);
  BOOST_ASSERT(signInterest.getName().get(-1).isParametersSha256Digest());

  bool receivedWrapperFetch = false;
  face.onSendInterest.connect([&](const Interest &interest) {
    if (!Name("/some").isPrefixOf(interest.getName()))
      return;
    BOOST_CHECK_EQUAL(interest.getName(), wrapper.getFullName());
    receivedWrapperFetch = true;
  });

  bool init_received = false;
  face.onSendData.connect([&](const Data &data) {
    //init
    BOOST_CHECK_EQUAL(data.getName(), signInterest.getName());
    const auto &content = data.getContent();
    content.parse();
    BOOST_CHECK_EQUAL(readString(content.get(tlv::Status)), std::to_string(static_cast<int>(ReplyCode::BadRequest)));
    BOOST_CHECK(data.getFreshnessPeriod().count() > 0);
    init_received = true;
  });

  advanceClocks(time::milliseconds(20), 10);
  face.receive(signInterest);
  advanceClocks(time::milliseconds(20), 10);
  BOOST_CHECK_EQUAL(init_received, true);
}

BOOST_AUTO_TEST_CASE(SignerFetchBadWrapper)
{
  util::DummyClientFace face(io, m_keyChain, {true, true});
  Signer signer(std::make_unique<MpsSigner>("/a/b/c/KEY/1234"), "/signer", face);
  signer.setDataVerifyCallback([](auto a) { return true; });
  signer.setSignatureVerifyCallback([](auto a) { return true; });

  //wrapper
  Data wrapper;
  wrapper.setName("/some/mps/wrapper/1234");
  wrapper.setContent(makeEmptyBlock(ndn::tlv::Content));
  wrapper.setFreshnessPeriod(time::seconds(1000));
  m_keyChain.sign(wrapper, signingWithSha256());

  //initiation interest
  Interest signInterest;
  signInterest.setName(Name("/signer/mps/sign"));
  Block appParam(ndn::tlv::ApplicationParameters);
  appParam.push_back(makeNestedBlock(tlv::UnsignedWrapperName, wrapper.getFullName()));
  signInterest.setApplicationParameters(appParam);
  signInterest.setCanBePrefix(false);
  signInterest.setMustBeFresh(true);
  BOOST_ASSERT(signInterest.getName().get(-1).isParametersSha256Digest());

  //result interest
  Interest resultInterest;
  resultInterest.setName(Name("/signer/mps/result-of")
                             .append(signInterest.getName().get(-1).value(), signInterest.getName().get(-1).value_size()));
  resultInterest.setCanBePrefix(true);
  resultInterest.setMustBeFresh(true);

  MultipartySchema schema;
  schema.signers.emplace_back(WildCardName(signer.m_signer->getSignerKeyName()));

  bool receivedWrapperFetch = false;
  face.onSendInterest.connect([&](const Interest &interest) {
    if (!Name("/some").isPrefixOf(interest.getName()))
      return;
    BOOST_CHECK_EQUAL(interest.getName(), wrapper.getFullName());
    receivedWrapperFetch = true;
  });

  bool result1_received = false;
  bool result2_received = false;
  bool init_received = false;
  face.onSendData.connect([&](const Data &data) {
    BOOST_CHECK(data.getFreshnessPeriod().count() > 0);
    if (Name("/signer/mps/result-of").isPrefixOf(data.getName())) {
      //result
      BOOST_CHECK_EQUAL(data.getName().size(), 5);
      BOOST_CHECK(data.getName().get(3).isGeneric());
      BOOST_CHECK_EQUAL_COLLECTIONS(data.getName().get(3).value_begin(), data.getName().get(3).value_end(),
                                    signInterest.getName().get(-1).value_begin(), signInterest.getName().get(-1).value_end());
      if (data.getName().get(-1).toVersion() == 0) {
        result1_received = true;
        const auto &content = data.getContent();
        content.parse();
        BOOST_CHECK_EQUAL(readString(content.get(tlv::Status)), std::to_string(static_cast<int>(ReplyCode::Processing)));
      }
      else {
        result2_received = true;
        const auto &content = data.getContent();
        content.parse();
        BOOST_CHECK_EQUAL(readString(content.get(tlv::Status)), std::to_string(static_cast<int>(ReplyCode::FailedDependency)));
      }
    }
    else {
      //init
      BOOST_CHECK_EQUAL(data.getName(), signInterest.getName());
      const auto &content = data.getContent();
      content.parse();
      BOOST_CHECK_EQUAL(readString(content.get(tlv::Status)), std::to_string(static_cast<int>(ReplyCode::Processing)));
      BOOST_CHECK_EQUAL(Name(content.get(tlv::ResultName).blockFromValue()), resultInterest.getName());
      init_received = true;
    }
  });

  advanceClocks(time::milliseconds(20), 10);
  face.receive(signInterest);
  advanceClocks(time::milliseconds(20), 10);
  BOOST_CHECK_EQUAL(init_received, true);
  BOOST_CHECK_EQUAL(receivedWrapperFetch, true);
  face.receive(resultInterest);
  advanceClocks(time::milliseconds(20), 10);
  BOOST_CHECK_EQUAL(result1_received, true);
  face.receive(wrapper);
  advanceClocks(time::milliseconds(20), 10);
  face.receive(resultInterest);
  advanceClocks(time::milliseconds(20), 10);
  BOOST_CHECK_EQUAL(result2_received, true);
}

BOOST_AUTO_TEST_CASE(InitiatorTest)
{
  m_keyChain.createIdentity("/initiator");
  util::DummyClientFace signerFace(io, m_keyChain, {true, true});
  Signer signer(std::make_unique<MpsSigner>("/a/b/c/KEY/1234"), "/signer", signerFace);
  signer.setDataVerifyCallback([](auto a) { return true; });
  signer.setSignatureVerifyCallback([](auto a) { return true; });

  util::DummyClientFace initiatorFace(io, m_keyChain, {true, true});
  Scheduler scheduler(io);
  Initiator initiator(MpsVerifier(), "/initiator", initiatorFace, scheduler, m_keyChain,
                      m_keyChain.getPib().getIdentity("/initiator").getDefaultKey().getName());
  initiator.addSigner(signer.m_signer->getSignerKeyName(), signer.m_signer->getPublicKey(), "/signer");
  initiatorFace.linkTo(signerFace);

  //data to test
  auto data1 = make_shared<Data>();
  data1->setName(Name("/a/b/c/d"));
  data1->setContent(Name("/1/2/3/4").wireEncode());
  data1->setFreshnessPeriod(time::seconds(1000));

  MultipartySchema schema;
  schema.signers.emplace_back(WildCardName(signer.m_signer->getSignerKeyName()));

  Name wrapperName;
  Name resultName;
  bool resultFetched = false;
  bool resultReplied = false;

  advanceClocks(time::milliseconds(20), 10);

  signerFace.onSendInterest.connect([&](const Interest &interest) {
    if (Name("/localhost/nfd").isPrefixOf(interest.getName()))
      return;
    //process
    if (Name("/initiator/mps/wrapper").isPrefixOf(interest.getName())) {
      const auto &content = interest.getApplicationParameters();
      BOOST_CHECK(!content.isValid());
    }
    else {
      std::cout << "interest: " << interest.getName() << std::endl;
      BOOST_CHECK(false);
    }
  });

  initiatorFace.onSendInterest.connect([&](const Interest &interest) {
    if (Name("/localhost/nfd").isPrefixOf(interest.getName()))
      return;
    //process
    if (Name("/signer/mps/sign").isPrefixOf(interest.getName())) {
      const auto &content = interest.getApplicationParameters();
      content.parse();
      BOOST_CHECK(content.get(tlv::UnsignedWrapperName).isValid());
      BOOST_CHECK_NO_THROW(wrapperName = Name(content.get(tlv::UnsignedWrapperName).blockFromValue()));
    }
    else if (Name("/signer/mps/result-of").isPrefixOf(interest.getName())) {
      BOOST_CHECK(resultName.isPrefixOf(interest.getName()));
      resultFetched = true;
    }
    else {
      std::cout << "interest: " << interest.getName() << std::endl;
      BOOST_CHECK(false);
    }
  });

  signerFace.onSendData.connect([&](const Data &data) {
    //process
    BOOST_CHECK(data.getFreshnessPeriod().count() > 0);
    if (Name("/signer/mps/sign").isPrefixOf(data.getName())) {
      const auto &content = data.getContent();
      content.parse();
      BOOST_CHECK(content.get(tlv::Status).isValid());
      BOOST_CHECK(content.get(tlv::ResultName).isValid());
      BOOST_CHECK(content.get(tlv::ResultAfter).isValid());
      BOOST_CHECK_EQUAL(readString(content.get(tlv::Status)), std::to_string(static_cast<int>(ReplyCode::Processing)));
      BOOST_CHECK_NO_THROW(resultName = Name(content.get(tlv::ResultName).blockFromValue()));
    }
    else if (Name("/signer/mps/result-of").isPrefixOf(data.getName())) {
      const auto &content = data.getContent();
      content.parse();
      BOOST_CHECK(content.get(tlv::Status).isValid());
      BOOST_CHECK(content.get(ndn::tlv::SignatureValue).isValid());
      BOOST_CHECK_EQUAL(readString(content.get(tlv::Status)), std::to_string(static_cast<int>(ReplyCode::OK)));
      resultReplied = true;
    }
    else {
      std::cout << "data: " << data.getName() << std::endl;
      BOOST_CHECK(false);
    }
  });

  initiatorFace.onSendData.connect([&](const Data &data) {
    //process
    BOOST_CHECK(data.getFreshnessPeriod().count() > 0);
    if (Name("/initiator/mps/wrapper").isPrefixOf(data.getName())) {
      const auto &content = data.getContent();
      content.parse();
      BOOST_CHECK(content.get(ndn::tlv::Data).isValid());
      BOOST_CHECK_EQUAL(content.get(ndn::tlv::Data), data1->wireEncode());
    }
    else {
      std::cout << "data: " << data.getName() << std::endl;
      BOOST_CHECK(false);
    }
  });

  bool success = false;
  advanceClocks(time::milliseconds(20), 10);
  initiator.multiPartySign(
      schema, data1,
      [&](auto data_ptr, auto signerListData) {
        const auto &content = signerListData.getContent();
        content.parse();
        MpsVerifier mpsVerifier;
        mpsVerifier.addCert(signer.m_signer->getSignerKeyName(), signer.m_signer->getPublicKey());
        BOOST_CHECK(content.get(tlv::MpsSignerList).isValid());
        BOOST_CHECK_NO_THROW(mpsVerifier.addSignerList(signerListData.getName(),
                                                       MpsSignerList(
                                                           content.get(tlv::MpsSignerList))));
        BOOST_CHECK(mpsVerifier.verifySignature(*data_ptr, schema));
        success = true;
      },
      [](auto reason) { BOOST_CHECK(false); });
  advanceClocks(time::milliseconds(20), 10);
  BOOST_CHECK(!wrapperName.empty());
  BOOST_CHECK(!resultName.empty());
  advanceClocks(time::milliseconds(20), 55);
  BOOST_CHECK(resultFetched);
  BOOST_CHECK(resultReplied);
  BOOST_CHECK_EQUAL(success, true);
  BOOST_CHECK(!wrapperName.empty());
}

BOOST_AUTO_TEST_CASE(InitiatorTestTimeout)
{
  m_keyChain.createIdentity("/initiator");
  MpsSigner mpsSigner("/a/b/c/KEY/1234");

  util::DummyClientFace initiatorFace(io, m_keyChain, {true, true});
  MpsVerifier mpsVerifier;
  Scheduler scheduler(io);
  Initiator initiator(mpsVerifier, "/initiator", initiatorFace, scheduler, m_keyChain,
                      m_keyChain.getPib().getIdentity("/initiator").getDefaultKey().getName());
  initiator.addSigner(mpsSigner.getSignerKeyName(), mpsSigner.getPublicKey(), "/signer");

  //data to test
  auto data1 = make_shared<Data>();
  data1->setName(Name("/a/b/c/d"));
  data1->setContent(Name("/1/2/3/4").wireEncode());
  data1->setFreshnessPeriod(time::seconds(1000));

  MultipartySchema schema;
  schema.signers.emplace_back(WildCardName(mpsSigner.getSignerKeyName()));

  Name wrapperName;

  advanceClocks(time::milliseconds(20), 10);

  initiatorFace.onSendInterest.connect([&](const Interest &interest) {
    if (Name("/localhost/nfd").isPrefixOf(interest.getName()))
      return;
    //process
    if (Name("/signer/mps/sign").isPrefixOf(interest.getName())) {
      const auto &content = interest.getApplicationParameters();
      content.parse();
      BOOST_CHECK(content.get(tlv::UnsignedWrapperName).isValid());
      BOOST_CHECK_NO_THROW(wrapperName = Name(content.get(tlv::UnsignedWrapperName).blockFromValue()));
    }
    else {
      std::cout << "interest: " << interest.getName() << std::endl;
    }
  });

  initiatorFace.onSendData.connect([&](const Data &data) {
    //process
    BOOST_CHECK(data.getFreshnessPeriod().count() > 0);
    BOOST_CHECK(false);
  });

  bool failure = false;
  advanceClocks(time::milliseconds(20), 10);
  initiator.multiPartySign(
      schema, data1,
      [](auto data_ptr, auto signerListData) {
        BOOST_CHECK(false);
      },
      [&](auto reason) { failure = true; });
  advanceClocks(time::milliseconds(20), 10);
  BOOST_CHECK(!wrapperName.empty());
  advanceClocks(time::milliseconds(100), 100);
  BOOST_CHECK_EQUAL(failure, true);
}

BOOST_AUTO_TEST_CASE(InitiatorTestUnauthorized)
{
  m_keyChain.createIdentity("/initiator");
  util::DummyClientFace signerFace(io, m_keyChain, {true, true});
  Signer signer(std::make_unique<MpsSigner>("/a/b/c/KEY/1234"), "/signer", signerFace);
  signer.setDataVerifyCallback([](auto a) { return true; });
  signer.setSignatureVerifyCallback([](auto a) { return false; });

  util::DummyClientFace initiatorFace(io, m_keyChain, {true, true});
  MpsVerifier mpsVerifier;
  Scheduler scheduler(io);
  Initiator initiator(mpsVerifier, "/initiator", initiatorFace, scheduler, m_keyChain,
                      m_keyChain.getPib().getIdentity("/initiator").getDefaultKey().getName());
  initiator.addSigner(signer.m_signer->getSignerKeyName(), signer.m_signer->getPublicKey(), "/signer");
  initiatorFace.linkTo(signerFace);

  //data to test
  auto data1 = make_shared<Data>();
  data1->setName(Name("/a/b/c/d"));
  data1->setContent(Name("/1/2/3/4").wireEncode());
  data1->setFreshnessPeriod(time::seconds(1000));

  MultipartySchema schema;
  schema.signers.emplace_back(WildCardName(signer.m_signer->getSignerKeyName()));

  Name wrapperName;
  bool replied = false;

  advanceClocks(time::milliseconds(20), 10);

  initiatorFace.onSendInterest.connect([&](const Interest &interest) {
    if (Name("/localhost/nfd").isPrefixOf(interest.getName()))
      return;
    //process
    if (Name("/signer/mps/sign").isPrefixOf(interest.getName())) {
      const auto &content = interest.getApplicationParameters();
      content.parse();
      BOOST_CHECK(content.get(tlv::UnsignedWrapperName).isValid());
      BOOST_CHECK_NO_THROW(wrapperName = Name(content.get(tlv::UnsignedWrapperName).blockFromValue()));
    }
    else {
      std::cout << "interest: " << interest.getName() << std::endl;
      BOOST_CHECK(false);
    }
  });

  signerFace.onSendData.connect([&](const Data &data) {
    //process
    BOOST_CHECK(data.getFreshnessPeriod().count() > 0);
    if (Name("/signer/mps/sign").isPrefixOf(data.getName())) {
      const auto &content = data.getContent();
      content.parse();
      BOOST_CHECK(content.get(tlv::Status).isValid());
      BOOST_CHECK_EQUAL(readString(content.get(tlv::Status)), std::to_string(static_cast<int>(ReplyCode::Unauthorized)));
      replied = true;
    }
    else {
      std::cout << "data: " << data.getName() << std::endl;
      BOOST_CHECK(false);
    }
  });

  bool failure = false;
  advanceClocks(time::milliseconds(20), 10);
  initiator.multiPartySign(
      schema, data1,
      [&](auto data_ptr, auto signerListData) {
        BOOST_CHECK(false);
      },
      [&](auto reason) { failure = true; });
  advanceClocks(time::milliseconds(20), 10);
  BOOST_CHECK(!wrapperName.empty());
  BOOST_CHECK(replied);
  advanceClocks(time::milliseconds(100), 10);
  BOOST_CHECK_EQUAL(failure, true);
}

BOOST_AUTO_TEST_CASE(InitiatorTestDataVerifyFail)
{
  m_keyChain.createIdentity("/initiator");
  util::DummyClientFace signerFace(io, m_keyChain, {true, true});
  Signer signer(std::make_unique<MpsSigner>("/a/b/c/KEY/1234"), "/signer", signerFace);
  signer.setDataVerifyCallback([](auto a) { return false; });
  signer.setSignatureVerifyCallback([](auto a) { return true; });

  util::DummyClientFace initiatorFace(io, m_keyChain, {true, true});
  MpsVerifier mpsVerifier;
  Scheduler scheduler(io);
  Initiator initiator(mpsVerifier, "/initiator", initiatorFace, scheduler, m_keyChain,
                      m_keyChain.getPib().getIdentity("/initiator").getDefaultKey().getName());
  initiator.addSigner(signer.m_signer->getSignerKeyName(), signer.m_signer->getPublicKey(), "/signer");
  initiatorFace.linkTo(signerFace);

  //data to test
  auto data1 = make_shared<Data>();
  data1->setName(Name("/a/b/c/d"));
  data1->setContent(Name("/1/2/3/4").wireEncode());
  data1->setFreshnessPeriod(time::seconds(1000));

  MultipartySchema schema;
  schema.signers.emplace_back(WildCardName(signer.m_signer->getSignerKeyName()));

  Name wrapperName;
  Name resultName;
  bool resultFetched = false;
  bool resultReplied = false;

  advanceClocks(time::milliseconds(20), 10);

  signerFace.onSendInterest.connect([&](const Interest &interest) {
    if (Name("/localhost/nfd").isPrefixOf(interest.getName()))
      return;
    //process
    if (Name("/initiator/mps/wrapper").isPrefixOf(interest.getName())) {
      const auto &content = interest.getApplicationParameters();
      BOOST_CHECK(!content.isValid());
    }
    else {
      std::cout << "interest: " << interest.getName() << std::endl;
      BOOST_CHECK(false);
    }
  });

  initiatorFace.onSendInterest.connect([&](const Interest &interest) {
    if (Name("/localhost/nfd").isPrefixOf(interest.getName()))
      return;
    //process
    if (Name("/signer/mps/sign").isPrefixOf(interest.getName())) {
      const auto &content = interest.getApplicationParameters();
      content.parse();
      BOOST_CHECK(content.get(tlv::UnsignedWrapperName).isValid());
      BOOST_CHECK_NO_THROW(wrapperName = Name(content.get(tlv::UnsignedWrapperName).blockFromValue()));
    }
    else if (Name("/signer/mps/result-of").isPrefixOf(interest.getName())) {
      BOOST_CHECK(resultName.isPrefixOf(interest.getName()));
      resultFetched = true;
    }
    else {
      std::cout << "interest: " << interest.getName() << std::endl;
      BOOST_CHECK(false);
    }
  });

  signerFace.onSendData.connect([&](const Data &data) {
    //process
    BOOST_CHECK(data.getFreshnessPeriod().count() > 0);
    if (Name("/signer/mps/sign").isPrefixOf(data.getName())) {
      const auto &content = data.getContent();
      content.parse();
      BOOST_CHECK(content.get(tlv::Status).isValid());
      BOOST_CHECK(content.get(tlv::ResultName).isValid());
      BOOST_CHECK(content.get(tlv::ResultAfter).isValid());
      BOOST_CHECK_EQUAL(readString(content.get(tlv::Status)), std::to_string(static_cast<int>(ReplyCode::Processing)));
      BOOST_CHECK_NO_THROW(resultName = Name(content.get(tlv::ResultName).blockFromValue()));
    }
    else if (Name("/signer/mps/result-of").isPrefixOf(data.getName())) {
      const auto &content = data.getContent();
      content.parse();
      BOOST_CHECK(content.get(tlv::Status).isValid());
      BOOST_CHECK_EQUAL(readString(content.get(tlv::Status)), std::to_string(static_cast<int>(ReplyCode::Unauthorized)));
      resultReplied = true;
    }
    else {
      std::cout << "data: " << data.getName() << std::endl;
      BOOST_CHECK(false);
    }
  });

  initiatorFace.onSendData.connect([&](const Data &data) {
    //process
    BOOST_CHECK(data.getFreshnessPeriod().count() > 0);
    if (Name("/initiator/mps/wrapper").isPrefixOf(data.getName())) {
      const auto &content = data.getContent();
      content.parse();
      BOOST_CHECK(content.get(ndn::tlv::Data).isValid());
      BOOST_CHECK_EQUAL(content.get(ndn::tlv::Data), data1->wireEncode());
    }
    else {
      std::cout << "data: " << data.getName() << std::endl;
      BOOST_CHECK(false);
    }
  });

  bool failure = false;
  advanceClocks(time::milliseconds(20), 10);
  initiator.multiPartySign(
      schema, data1,
      [&](auto data_ptr, auto signerListData) {
        BOOST_CHECK(false);
      },
      [&](auto reason) { failure = true; });
  advanceClocks(time::milliseconds(20), 10);
  BOOST_CHECK(!wrapperName.empty());
  BOOST_CHECK(!resultName.empty());
  advanceClocks(time::milliseconds(100), 10);
  BOOST_CHECK(resultFetched);
  BOOST_CHECK(resultReplied);
  BOOST_CHECK_EQUAL(failure, true);
}

BOOST_AUTO_TEST_CASE(InitiatorTestBadSignature)
{
  m_keyChain.createIdentity("/initiator");
  util::DummyClientFace signerFace(io, m_keyChain, {true, true});
  Signer signer(std::make_unique<MpsSigner>("/a/b/c/KEY/1234"), "/signer", signerFace);
  signer.setDataVerifyCallback([](auto a) { return true; });
  signer.setSignatureVerifyCallback([](auto a) { return true; });

  BOOST_CHECK(!blsPublicKeyIsEqual(&signer.m_signer->getPublicKey(), &MpsSigner("/a/b/c/KEY/1234").getPublicKey()));

  util::DummyClientFace initiatorFace(io, m_keyChain, {true, true});
  MpsVerifier mpsVerifier;
  Scheduler scheduler(io);
  Initiator initiator(mpsVerifier, "/initiator", initiatorFace, scheduler, m_keyChain,
                      m_keyChain.getPib().getIdentity("/initiator").getDefaultKey().getName());
  initiator.addSigner(signer.m_signer->getSignerKeyName(), MpsSigner("/a/b/c/KEY/1234").getPublicKey(), "/signer");  // bad key
  initiatorFace.linkTo(signerFace);

  //data to test
  auto data1 = make_shared<Data>();
  data1->setName(Name("/a/b/c/d"));
  data1->setContent(Name("/1/2/3/4").wireEncode());
  data1->setFreshnessPeriod(time::seconds(1000));

  MultipartySchema schema;
  schema.signers.emplace_back(WildCardName(signer.m_signer->getSignerKeyName()));

  Name wrapperName;
  Name resultName;
  bool resultFetched = false;
  bool resultReplied = false;

  advanceClocks(time::milliseconds(20), 10);

  signerFace.onSendInterest.connect([&](const Interest &interest) {
    if (Name("/localhost/nfd").isPrefixOf(interest.getName()))
      return;
    //process
    if (Name("/initiator/mps/wrapper").isPrefixOf(interest.getName())) {
      const auto &content = interest.getApplicationParameters();
      BOOST_CHECK(!content.isValid());
    }
    else {
      std::cout << "interest: " << interest.getName() << std::endl;
      BOOST_CHECK(false);
    }
  });

  initiatorFace.onSendInterest.connect([&](const Interest &interest) {
    if (Name("/localhost/nfd").isPrefixOf(interest.getName()))
      return;
    //process
    if (Name("/signer/mps/sign").isPrefixOf(interest.getName())) {
      const auto &content = interest.getApplicationParameters();
      content.parse();
      BOOST_CHECK(content.get(tlv::UnsignedWrapperName).isValid());
      BOOST_CHECK_NO_THROW(wrapperName = Name(content.get(tlv::UnsignedWrapperName).blockFromValue()));
    }
    else if (Name("/signer/mps/result-of").isPrefixOf(interest.getName())) {
      BOOST_CHECK(resultName.isPrefixOf(interest.getName()));
      resultFetched = true;
    }
    else {
      std::cout << "interest: " << interest.getName() << std::endl;
      BOOST_CHECK(false);
    }
  });

  signerFace.onSendData.connect([&](const Data &data) {
    //process
    BOOST_CHECK(data.getFreshnessPeriod().count() > 0);
    if (Name("/signer/mps/sign").isPrefixOf(data.getName())) {
      const auto &content = data.getContent();
      content.parse();
      BOOST_CHECK(content.get(tlv::Status).isValid());
      BOOST_CHECK(content.get(tlv::ResultName).isValid());
      BOOST_CHECK(content.get(tlv::ResultAfter).isValid());
      BOOST_CHECK_EQUAL(readString(content.get(tlv::Status)), std::to_string(static_cast<int>(ReplyCode::Processing)));
      BOOST_CHECK_NO_THROW(resultName = Name(content.get(tlv::ResultName).blockFromValue()));
    }
    else if (Name("/signer/mps/result-of").isPrefixOf(data.getName())) {
      const auto &content = data.getContent();
      content.parse();
      BOOST_CHECK(content.get(tlv::Status).isValid());
      BOOST_CHECK(content.get(ndn::tlv::SignatureValue).isValid());
      BOOST_CHECK_EQUAL(readString(content.get(tlv::Status)), std::to_string(static_cast<int>(ReplyCode::OK)));
      resultReplied = true;
    }
    else {
      std::cout << "data: " << data.getName() << std::endl;
      BOOST_CHECK(false);
    }
  });

  initiatorFace.onSendData.connect([&](const Data &data) {
    //process
    BOOST_CHECK(data.getFreshnessPeriod().count() > 0);
    if (Name("/initiator/mps/wrapper").isPrefixOf(data.getName())) {
      const auto &content = data.getContent();
      content.parse();
      BOOST_CHECK(content.get(ndn::tlv::Data).isValid());
      BOOST_CHECK_EQUAL(content.get(ndn::tlv::Data), data1->wireEncode());
    }
    else {
      std::cout << "data: " << data.getName() << std::endl;
      BOOST_CHECK(false);
    }
  });

  bool failure = false;
  advanceClocks(time::milliseconds(20), 10);
  initiator.multiPartySign(
      schema, data1,
      [&](auto data_ptr, auto signerListData) {
        BOOST_CHECK(false);
      },
      [&](auto reason) { failure = true; });
  advanceClocks(time::milliseconds(20), 10);
  BOOST_CHECK(!wrapperName.empty());
  BOOST_CHECK(!resultName.empty());
  advanceClocks(time::milliseconds(100), 10);
  BOOST_CHECK(resultFetched);
  BOOST_CHECK(resultReplied);
  BOOST_CHECK_EQUAL(failure, true);
}

//TODO get schema with key(multiple round)

BOOST_AUTO_TEST_SUITE_END()  // TestMpsSignerList

}  // namespace tests
}  // namespace mps
}  // namespace ndn