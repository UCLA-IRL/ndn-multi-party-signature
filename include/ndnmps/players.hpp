#ifndef NDNMPS_PLAYERS_HPP
#define NDNMPS_PLAYERS_HPP

#include <iostream>
#include <map>
#include <ndn-cxx/data.hpp>
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/util/scheduler.hpp>

#include "crypto-players.hpp"
#include "mps-signer-list.hpp"
#include "ndnmps/schema.hpp"

namespace ndn {

// TODO players that handles all protocols and network interactions
class Signer : public MpsSigner {
private:
  Name m_prefix;
  Face& m_face;
  function<bool(const Data&)> m_dataVerifyCallback;
  function<bool(const Interest&)> m_interestVerifyCallback;
  std::list<RegisteredPrefixHandle> m_handles;

  struct RequestInfo {
    ReplyCode status;
    uint64_t versionCount;
    optional<Block> value;
    RequestInfo();
  };
  std::map<Buffer, RequestInfo> m_states;
  std::map<Name, Buffer> m_unsignedNames;
public:
  /**
   * @brief Generate public and secret key pair.
   */
  Signer(MpsSigner mpsSigner, const Name& prefix, Face& face);

  virtual ~Signer();

  void
  setDataVerifyCallback(const function<bool(const Data&)>& func);
  void
  setSignatureVerifyCallback(const function<bool(const Interest&)>& func);

private:
  void
  onInvocation(const Interest&);

  void
  onResult(const Interest&);

  void
  reply(const Name& interestName, ConstBufferPtr requestId) const;

  void
  replyError(const Name& interestName, ReplyCode errorCode) const;

  static void
  onRegisterFail(const Name& prefix, const std::string& reason);

  void
  onData(const Interest&, const Data& data);

  void
  onNack(const Interest&, const lp::Nack& nack);

  void
  onTimeout(const Interest&);
};

typedef function<void(bool)> VerifyFinishCallback;

class Verifier : public MpsVerifier {
private:
  struct VerificationRecord {
    shared_ptr<const Data> data;
    shared_ptr<const MultipartySchema> schema;
    const VerifyFinishCallback callback;
    uint32_t itemLeft;
  };
  std::map<uint32_t, VerificationRecord> m_queue;
  std::map<Name, std::set<uint32_t>> m_index;
  Face& m_face;
  function<bool(const Data&)> m_certVerifyCallback;

public:
  Verifier(MpsVerifier v, Face& face);

  void
  setCertVerifyCallback(const function<bool(const Data&)>& func);

  void
  asyncVerifySignature(shared_ptr<const Data> data, shared_ptr<const MultipartySchema> schema, const VerifyFinishCallback& callback);

private:
  void
  removeAll(const Name& name);

  void
  satisfyItem(const Name& itemName);

  void
  onData(const Interest&, const Data& data);

  void
  onNack(const Interest&, const lp::Nack& nack);

  void
  onTimeout(const Interest&);
};

typedef function<void(std::shared_ptr<Data> data, Data signerListData)> SignatureFinishCallback;
typedef function<void(const std::string& reason)> SignatureFailureCallback;

class Initiator : public MpsAggregater {
private:
  struct InitiationRecord {
    const MultipartySchema schema;
    std::shared_ptr<Data> unsignedData;
    SignatureFinishCallback onSuccess;
    SignatureFailureCallback onFailure;
    Data wrapper;
    std::map<Name, blsSignature> signaturePieces;
    scheduler::EventId eventId;
    InitiationRecord(const MultipartySchema& trySchema, std::shared_ptr<Data> data,
                     const SignatureFinishCallback& successCb, const SignatureFailureCallback& failureCb);
  };
  MpsVerifier m_verifier;
  Face& m_face;
  const Name m_prefix;
  Scheduler& m_scheduler;
  std::map<Name, Name> m_keyToPrefix;
  optional<RegisteredPrefixHandle> m_handle;
  std::map<uint32_t, InitiationRecord> m_records;
  std::map<Name, uint32_t> m_wrapToId;
  std::function<void(Interest&)> m_interestSigningCallback;
  variant<std::pair<KeyChain&, Name>, MpsSigner> m_signer;
public:
  Initiator(const MpsVerifier& verifier, const Name& prefix, Face& face, Scheduler& scheduler,
            KeyChain& keyChain, const Name& signingKeyName);

  Initiator(const MpsVerifier& verifier, const Name& prefix, Face& face, Scheduler& scheduler,
            const MpsSigner& dataSigner);
  virtual ~Initiator();

  void
  addSigner(const Name& keyName, const Name& prefix);

  void
  addSigner(const Name& keyName, const blsPublicKey& keyValue, const Name& prefix);

  void
  setInterestSignCallback(std::function<void(Interest&)> func);

  void
  multiPartySign(const MultipartySchema& schema, std::shared_ptr<Data> unfinishedData,
                 const SignatureFinishCallback& successCb, const SignatureFailureCallback& failureCb);

private:
  void
  onWrapperFetch(const Interest&);

  void
  onData(uint32_t id, const Name &keyName, const Interest&, const Data& data);

  void
  onNack(uint32_t id, const Interest&, const lp::Nack& nack);

  void
  onTimeout(uint32_t id, const Interest&);

  static void
  onRegisterFail(const Name& prefix, const std::string& reason);

  void
  onSignTimeout(uint32_t id);

  void
  successCleanup(uint32_t id);
};

}  // namespace ndn

#endif  // NDNMPS_PLAYERS_HPP