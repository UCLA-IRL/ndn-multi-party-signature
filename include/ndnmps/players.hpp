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
  function<bool(const Data&, const Name& schema)> m_dataVerifyCallback;
  function<bool(const Interest&)> m_interestVerifyCallback;
  std::list<RegisteredPrefixHandle> m_handles;

  struct RequestInfo {
    ReplyCode status;
    int versionCount;
    Name signerListName;
    optional<Block> value;
    RequestInfo();
  };
  std::unordered_map<int, RequestInfo> m_states;
  std::unordered_map<Name, int> m_unsignedNames;
public:
  /**
   * @brief Generate public and secret key pair.
   */
  Signer(MpsSigner mpsSigner, const Name& prefix, Face& face);

  virtual ~Signer();

  void
  setDataVerifyCallback(const function<bool(const Data&, const Name& schema)>& func);
  void
  setSignatureVerifyCallback(const function<bool(const Interest&)>& func);

private:
  void
  onInvocation(const Interest&);

  void
  onResult(const Interest&);

  void
  reply(const Name& interestName, int requestId) const;

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
    int itemLeft;
  };
  std::map<int, VerificationRecord> m_queue;
  int m_queueLast = 0;
  std::map<Name, std::set<int>> m_index;
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
    const MultipartySchema& schema;
    std::shared_ptr<Data> unsignedData;
    const SignatureFinishCallback& onSuccess;
    const SignatureFailureCallback& onFailure;
    Data wrapper;
    std::map<Name, blsSignature> signaturePieces;
    scheduler::EventId eventId;
    InitiationRecord(const MultipartySchema& trySchema, std::shared_ptr<Data> data,
                     const SignatureFinishCallback& successCb, const SignatureFailureCallback& failureCb);
  };
  MpsVerifier& m_verifier;
  Face& m_face;
  Scheduler& m_scheduler;
  std::map<Name, Name> m_keyToPrefix;
  const Name m_prefix;
  optional<RegisteredPrefixHandle> m_handle;
  std::map<int, InitiationRecord> m_records;
  std::map<Name, int> m_wrapToId;
  int m_lastId;
  std::function<void(Interest&)> m_interestSigningCallback;

public:
  Initiator(MpsVerifier& verifier, const Name& prefix, Face& face, Scheduler& scheduler);
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
  onData(int id, const Name& keyName, const Interest&, const Data& data);

  void
  onNack(int id, const Interest&, const lp::Nack& nack);

  void
  onTimeout(int id, const Interest&);

  static void
  onRegisterFail(const Name& prefix, const std::string& reason);

  void
  onSignTimeout(int id);

  void
  successCleanup(int id);
};

}  // namespace ndn

#endif  // NDNMPS_PLAYERS_HPP