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

/**
 * The signer class class that handles functionality in the multi-signing protocol.
 * Note that it is different from MpsSigner, which only provides signing and packet encoding.
 */
class Signer {
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
  std::unique_ptr<MpsSigner> m_signer;

public:
  /**
   * Construct the signer participant in the protocol
   * @param mpsSigner the signer that signs data
   * @param prefix the routable prefix to register prefix to
   * @param face the network interface.
   */
  Signer(std::unique_ptr<MpsSigner> mpsSigner, const Name& prefix, Face& face);

  /**
   * the destructor. Currently remove the prefix registration.
   */
  virtual ~Signer();

  /**
   * Set the behavior when verifying the unsigned data.
   * Default to returning false at all time.
   * @param func the function to be called when verifying a unsigned data for endorsement.
   */
  void
  setDataVerifyCallback(const function<bool(const Data&)>& func);

  /**
   * Set the behavior when verifying the signature from the initiator
   * @param func the function to verify the initiator signature.
   */
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

/**
 * The class for verifier, which will fetch the unknown data.
 * Note that this is different from MpsVerifier, which will not fetch the data from network.
 */
class Verifier {
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
  bool m_fetchKeys;

public:
  std::unique_ptr<MpsVerifier> m_verifier;

public:
  /**
   * Construct the verifier.
   * @param v the MpsVerifier to use that contains initial key chain.
   * @param face the network interface.
   * @param fetchKeys if true, fetch unknown keys
   */
  Verifier(std::unique_ptr<MpsVerifier> verifier, Face& face, bool fetchKeys = false);

  /**
   * set the behavior when received a new certificate.
   * @param func the function to call to verify the new certificate.
   */
  void
  setCertVerifyCallback(const function<bool(const Data&)>& func);

  /**
   * Asynchronously verifies the signature of a data.
   * @param data the data to be verified.
   * @param schema the trust schema to verify against.
   * @param callback the callback then the verification finished. It will be called eventually.
   */
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

/**
 * The initiator class for the multisigning protocol.
 */
class Initiator : public MpsAggregator {
private:
  struct InitiationRecord {
    const MultipartySchema schema;
    std::shared_ptr<Data> unsignedData;
    SignatureFinishCallback onSuccess;
    SignatureFailureCallback onFailure;
    Data wrapper;
    std::map<Name, blsSignature> signaturePieces;
    std::vector<Name> availableKeys;
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
  variant<std::pair<KeyChain&, Name>, MpsSigner> m_signer;

public:
  /**
   * Construct the initiator. The data are signed with NDN-cxx keychain.
   * @param verifier the verifier to verify the signature piece.
   * @param prefix the routable prefix for this initiator
   * @param face the network interface.
   * @param scheduler the scheduler to schedule timer events.
   * @param keyChain the NDN-cxx keychain for signing data.
   * @param signingKeyName the signing key name to be used.
   */
  Initiator(const MpsVerifier& verifier, const Name& prefix, Face& face, Scheduler& scheduler,
            KeyChain& keyChain, const Name& signingKeyName);

  /**
   * Construct the initiator. The data are signed with BLS/MPS signer
   * @param verifier the verifier to verify the signature piece.
   * @param prefix the routable prefix for this initiator
   * @param face the network interface.
   * @param scheduler the scheduler to schedule timer events.
   * @param dataSigner the BLS/MPS signer to sign the data.
   */
  Initiator(const MpsVerifier& verifier, const Name& prefix, Face& face, Scheduler& scheduler,
            const MpsSigner& dataSigner);

  /**
   * The destructor. Currently remove the prefix registered.
   */
  virtual ~Initiator();

  /**
   * Add the routing prefix of signer. the public key need to be already in the verifier chain.
   * @param keyName the key name of the signer.
   * @param prefix the routable prefix of the signer.
   */
  void
  addSigner(const Name& keyName, const Name& prefix);

  /**
   * Add the routing prefix of signer. Used for also add public key to internal verifier chain
   * @param keyName the key name of the signer.
   * @param keyValue the public key of the signer.
   * @param prefix the routable prefix of the signer.
   */
  void
  addSigner(const Name& keyName, const blsPublicKey& keyValue, const Name& prefix);

  /**
   * Initiate the multi-party signing.
   * @param schema the schema to satisfy with the signature.
   * @param unfinishedData the unsigned data to be (multi-) signed.
   * @param successCb the callback then the data finished signing. Also returns the signer list.
   * @param failureCb the callback then the data failed to be signed. the reason will be returned.
   */
  void
  multiPartySign(const MultipartySchema& schema, std::shared_ptr<Data> unfinishedData,
                 const SignatureFinishCallback& successCb, const SignatureFailureCallback& failureCb);

private:
  void
  onWrapperFetch(const Interest&);

  void
  onData(uint32_t id, const Name& keyName, const Data& data);

  void
  onNack(uint32_t id, const Name& keyName, const Interest&, const lp::Nack& nack);

  void
  onTimeout(uint32_t id, const Name& keyName, const Interest&);

  static void
  onRegisterFail(const Name& prefix, const std::string& reason);

  void
  onSignTimeout(uint32_t id);

  void
  successCleanup(uint32_t id);

  void
  keyLossTimeout(uint32_t id, const Name& keyName);
};

}  // namespace ndn

#endif  // NDNMPS_PLAYERS_HPP