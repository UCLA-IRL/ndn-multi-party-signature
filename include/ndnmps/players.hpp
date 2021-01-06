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
class Signer {
private:
  MpsSigner m_mpsSigner;

public:
  /**
   * @brief Generate public and secret key pair.
   */
  Signer(MpsSigner mpsSigner);

  const MpsSigner&
  getMpsSigner() const;

  MpsSigner&
  getMpsSigner();
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
    setCertVerifyCallback(function<bool(const Data&)> func);

    void
    asyncVerifySignature(const Data& data, const MultipartySchema& schema, const VerifyFinishCallback& callback);

private:
    void
    removeAll(const Name& name);

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