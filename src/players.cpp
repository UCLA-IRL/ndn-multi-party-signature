#include "ndnmps/players.hpp"

#include <utility>

namespace ndn {

Signer::Signer(MpsSigner mpsSigner)
            : m_mpsSigner(std::move(mpsSigner))
{
}

const MpsSigner&
Signer::getMpsSigner() const
{
    return m_mpsSigner;
}

MpsSigner&
Signer::getMpsSigner()
{
    return m_mpsSigner;
}

Verifier::Verifier(MpsVerifier verifier, Face& face)
        : MpsVerifier(std::move(verifier)), m_face(face)
{
}

void
Verifier::setCertVerifyCallback(function<bool(const Data&)> func)
{
    m_certVerifyCallback = func;
}

void
Verifier::asyncVerifySignature(const Data& data, const MultipartySchema& schema, const VerifyFinishCallback& callback)
{
    if (readyToVerify(data)) {
        callback(verifySignature(data, schema));
    } else {
        //store, fetch and wait
        QueueRecord r{data, schema, callback, 0};
        for (const auto& item : itemsToFetch(data)) {
            Interest interest(item);
            interest.setCanBePrefix(false);
            interest.setMustBeFresh(true);
            m_face.expressInterest(interest,
                                   [this](auto && PH1, auto && PH2) { onData(PH1, PH2); },
                                   [this](auto && PH1, auto && PH2) { onNack(PH1, PH2); },
                                   [this](auto && PH1) { onTimeout(PH1); });
            m_index[item].insert(m_queueLast);
            r.itemLeft ++;
        }
        m_queue.emplace(m_queueLast, r);
        m_queueLast ++;
    }
}

void
Verifier::removeAll(const Name& name) {
    for (auto i : m_index[name]) {
        //remove them
        if (m_queue.count(i) != 0) {
            m_queue[i].callback(false);
            m_queue.erase(i);
        }
    }
    m_index.erase(name);
}

void
Verifier::onData(const Interest& interest, const Data& data) {
    if (security::Certificate::isValidName(interest.getName())) {
        //certificate
        if (m_certVerifyCallback && m_certVerifyCallback(data)) {
            const auto& c = data.getContent();
            blsPublicKey key;
            int ret = blsPublicKeyDeserialize(&key, c.value(), c.value_size());
            if (ret == 0) {
                // decode failure
                removeAll(interest.getName());
                std::stringstream ss;
                ss << "Certificate cannot be decoded for " << interest.getName();
                NDN_THROW(std::runtime_error(ss.str()));
            }
            addCert(interest.getName(), key);
            for (auto i : m_index[interest.getName()]) {
                if (m_queue.count(i) != 0) {
                    m_queue[i].itemLeft --;
                    if (m_queue[i].itemLeft == 0) {
                        QueueRecord r = m_queue[i];
                        m_queue.erase(i);
                        asyncVerifySignature(r.data, r.schema, r.callback);
                    }
                }
            }
            m_index.erase(interest.getName());
        } else {
            removeAll(interest.getName());
            std::stringstream ss;
            ss << "Certificate cannot be verified for " << interest.getName();
            NDN_THROW(std::runtime_error(ss.str()));
        }
    } else {
        //signer list
        data.getContent().parse();
        for (const auto& item : data.getContent().elements()) {
            if (item.type() == tlv::MpsSignerList) {
                addSignerList(interest.getName(), MpsSignerList(item));
                for (auto i : m_index[interest.getName()]) {
                    if (m_queue.count(i) != 0) {
                        m_queue[i].itemLeft --;
                        if (m_queue[i].itemLeft == 0) {
                            QueueRecord r = m_queue[i];
                            m_queue.erase(i);
                            asyncVerifySignature(r.data, r.schema, r.callback);
                        }
                    }
                }
                m_index.erase(interest.getName());
                return;
            }
        }
        removeAll(interest.getName());
        std::stringstream ss;
        ss << "signer list not found in " << interest.getName();
        NDN_THROW(std::runtime_error(ss.str()));
    }
}

void
Verifier::onNack(const Interest& interest, const lp::Nack& nack) {
    removeAll(interest.getName());

    std::stringstream ss;
    ss << "Received NACK with reason " << nack.getReason() << " for " << interest.getName();
    NDN_THROW(std::runtime_error(ss.str()));
}

void
Verifier::onTimeout(const Interest& interest) {
    removeAll(interest.getName());

    std::stringstream ss;
    ss << "interest time out for " << interest.getName();
    NDN_THROW(std::runtime_error(ss.str()));
}

} // namespace ndn