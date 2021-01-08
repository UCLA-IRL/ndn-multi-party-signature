#ifndef NDNMPS_PLAYERS_HPP
#define NDNMPS_PLAYERS_HPP

#include "ndnmps/schema.hpp"
#include "mps-signer-list.hpp"
#include "crypto-players.hpp"
#include <ndn-cxx/data.hpp>
#include <ndn-cxx/face.hpp>

#include <iostream>
#include <map>

namespace ndn {


// TODO players that handles all protocols and network interactions
class Signer: public MpsSigner {
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
  std::map<int, RequestInfo> m_states;
  std::map<Name, int> m_unsignedNames;
  uint64_t m_nextRequestId;
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

class Verifier: public MpsVerifier {
private:
    struct QueueRecord {
        const Data& data;
        const MultipartySchema& schema;
        const VerifyFinishCallback& callback;
        int itemLeft;
    };
    std::map<int, QueueRecord> m_queue;
    int m_queueLast = 0;
    std::map<Name, std::set<int>> m_index;
    Face& m_face;
    function<bool(const Data&)> m_certVerifyCallback;
public:
    Verifier(MpsVerifier v, Face& face);

    void
    setCertVerifyCallback(const function<bool(const Data&)>& func);

    void
    asyncVerifySignature(const Data& data, const MultipartySchema& schema, const VerifyFinishCallback& callback);

private:
    void
    removeAll(const Name& name);

    void
    satisfyItem(const Name &itemName);

    void
    onData(const Interest&, const Data& data);

    void
    onNack(const Interest&, const lp::Nack& nack);

    void
    onTimeout(const Interest&);
};

typedef function<void(const Data& signedData)> SignatureFinishCallback;
typedef function<void(const Data& unfinishedData, const std::string& reason)> SignatureFailureCallback;

class Initiator {
public:

  Initiator();

  void
  startSigningProcess(const MultipartySchema& schema, const Data& unfinishedData,
                      const SignatureFinishCallback& successCb, const SignatureFailureCallback& failureCab);

private:
  void
  onTimeout();

  void
  onNack();

  void
  onData();
};

}  // namespace ndn

#endif // NDNMPS_PLAYERS_HPP