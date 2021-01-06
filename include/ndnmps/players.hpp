#ifndef NDNMPS_PLAYERS_HPP
#define NDNMPS_PLAYERS_HPP

#include "ndnmps/schema.hpp"
#include "mps-signer-list.hpp"
#include "crypto-players.hpp"
#include <ndn-cxx/data.hpp>

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

class Verifier {
private:
  MpsVerifier m_verifier;

public:
  Verifier(MpsVerifier verifier);

  const MpsVerifier&
  getMpsVerifier() const;

    MpsVerifier&
  getMpsVerifier();
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