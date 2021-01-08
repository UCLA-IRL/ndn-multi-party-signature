#include "ndnmps/players.hpp"
#include "ndn-cxx/util/logger.hpp"
#include "ndn-cxx/util/random.hpp"

#include <utility>

namespace ndn {

NDN_LOG_INIT(ndnmps.players);

Signer::Signer(MpsSigner mpsSigner, const Name& prefix, Face& face)
            : MpsSigner(std::move(mpsSigner)), m_prefix(prefix), m_face(face)
{
    Name invocationPrefix = m_prefix;
    invocationPrefix.append("mps").append("sign");
    m_handles.push_back(m_face.setInterestFilter(invocationPrefix, [&](auto &&, auto && PH2) { onInvocation(PH2); }, nullptr,
                                           Signer::onRegisterFail));

    Name resultPrefix = m_prefix;
    resultPrefix.append("mps").append("result-of");
    m_handles.push_back(m_face.setInterestFilter(resultPrefix, [&](auto &&, auto && PH2) { onResult(PH2); }, nullptr,
                                           Signer::onRegisterFail));

    m_nextRequestId = random::generateSecureWord64();
}

Signer::~Signer() {
    for (auto& i : m_handles) {
        i.unregister();
    }
}

void
Signer::setDataVerifyCallback(const function<bool(const Data&, const Name& schema)>& func) {
    m_dataVerifyCallback = func;
}

void
Signer::setSignatureVerifyCallback(const function<bool(const Interest&)>& func) {
    m_interestVerifyCallback = func;
}

Signer::RequestInfo::RequestInfo()
: status(ReplyCode::Processing), versionCount(0), value(nullopt){}

void
Signer::onInvocation(const Interest& interest) {
    RequestInfo info;
    if (!m_interestVerifyCallback || !m_interestVerifyCallback(interest)) {
        replyError(interest.getName(), ReplyCode::Unauthorized);
        return;
    }
    //parse
    const auto& b = interest.getApplicationParameters();
    b.parse();
    Name wrapperName;
    try {
        for (const auto &item : b.elements()) {
            if (item.type() == tlv::UnsignedWrapperName && wrapperName.empty()) {
                wrapperName = Name(item.blockFromValue());
            } else if (item.type() == tlv::SignerListName && info.signerListName.empty()) {
                info.signerListName = Name(item.blockFromValue());
            } else {
                NDN_THROW(std::runtime_error("Bad element type in signer's request"));
            }
        }
        if (wrapperName.empty() || info.signerListName.empty() || !wrapperName.at(-1).isImplicitSha256Digest()) {
            NDN_THROW(std::runtime_error("Block Element not found"));
        }
    } catch (const std::exception& e) {
        NDN_LOG_ERROR("Got error in decoding invocation request: " << e.what());
        replyError(interest.getName(), ReplyCode::BadRequest);
        return;
    }

    //add
    m_states.emplace(m_nextRequestId, info);
    m_unsignedNames.emplace(wrapperName, m_nextRequestId);
    reply(interest.getName(), m_nextRequestId);
    m_nextRequestId ++;

    //fetch
    Interest fetchInterest(wrapperName);
    fetchInterest.setCanBePrefix(false);
    fetchInterest.setMustBeFresh(true);
    m_face.expressInterest(fetchInterest,
                           [&](auto && PH1, auto && PH2) { onData(PH1, PH2); },
                           [&](auto && PH1, auto && PH2) { onNack(PH1, PH2); },
                           [&](auto && PH1) { onTimeout(PH1); });
}

void
Signer::onResult(const Interest& interest) {
    //parse
    if (interest.getName().size() != m_prefix.size() + 3) {
        NDN_LOG_ERROR("Bad result request length");
        replyError(interest.getName(), ReplyCode::BadRequest);
    }
    const auto& resultId = readString(interest.getName().at(m_prefix.size() + 2));
    uint64_t requestId = std::stoll(resultId.substr(0, resultId.find('_')));

    const auto& it = m_states.find(requestId);
    if (it != m_states.end() && it->second.status == ReplyCode::Processing){
        it->second.versionCount ++;
    }
    if (it->second.status == ReplyCode::OK && !it->second.value.has_value()) {
        it->second.status = ReplyCode::InternalError;
    }
    reply(interest.getName(), requestId);
    if (it != m_states.end() && it->second.status != ReplyCode::Processing){
        m_states.erase(it);
    }
}

void
Signer::reply(const Name& interestName, int requestId) const {
    const auto& it = m_states.find(requestId);
    if (it == m_states.end()) {
        replyError(interestName, ReplyCode::NotFound);
        return;
    }
    Data data;
    data.setName(interestName);
    Block block(tlv::Content);
    block.push_back(makeStringBlock(tlv::Status,
                                    std::to_string(static_cast<int>(it->second.status))));
    if (it->second.status == ReplyCode::Processing) {
        block.push_back(makeNonNegativeIntegerBlock(tlv::ResultAfter, 1000));
        Name newResultName = m_prefix;
        newResultName.append("mps").append("result-of").append(std::to_string(requestId) + "_" + std::to_string(it->second.versionCount));
        block.push_back(makeNestedBlock(tlv::ResultName, newResultName));
    } else if (it->second.status == ReplyCode::OK) {
        block.push_back(*it->second.value);
    } else {
        replyError(interestName, it->second.status);
        return;
    }
    data.setContent(block);
    //TODO Sign?
    m_face.put(data);
}

void
Signer::replyError(const Name& interestName, ReplyCode errorCode) const {
    Data data;
    data.setName(interestName);
    data.setContent(Block(tlv::Content, makeStringBlock(tlv::Status,
            std::to_string(static_cast<int>(errorCode)))));
    //TODO Sign?
    m_face.put(data);
}

void
Signer::onRegisterFail(const Name& prefix, const std::string& reason){
    NDN_LOG_ERROR("Fail to register prefix " << prefix.toUri() << " because " << reason);
}

void
Signer::onData(const Interest& interest, const Data& data)
{
    ReplyCode code=ReplyCode::OK;

    //check digest
    if (interest.getName() != data.getFullName()) {
        NDN_LOG_ERROR("Data verification failed");
        code = ReplyCode::FailedDependency;
    }

    //check unsigned data
    Data unsignedData;
    if (code == ReplyCode::OK) {
        try {
            unsignedData = Data(data.getContent().blockFromValue());
        } catch (const std::exception &e) {
            NDN_LOG_ERROR("Unsigned Data encoding fail");
            code = ReplyCode::BadRequest;
        }
    }

    int id;
    if(m_unsignedNames.count(interest.getName()) != 0) {
        id = m_unsignedNames.at(interest.getName());
        m_unsignedNames.erase(interest.getName());
    } else {
        return;
    }
    if (m_states.count(id) == 0) return;
    RequestInfo& state = m_states.at(id);
    if (code == ReplyCode::OK) {
        if (!m_dataVerifyCallback || !m_dataVerifyCallback(data, state.signerListName)) {
            NDN_LOG_ERROR("Unsigned Data verification fail");
            code = ReplyCode::Unauthorized;
        }
    }

    state.status = code;
    if (code != ReplyCode::OK) {
        return;
    }
    //sign
    state.value = getSignature(unsignedData,
            SignatureInfo(static_cast<tlv::SignatureTypeValue>(tlv::SignatureSha256WithBls), KeyLocator(state.signerListName)));
}

void
Signer::onNack(const Interest& interest, const lp::Nack& nack)
{
    NDN_LOG_ERROR("Received NACK with reason " << nack.getReason() << " for " << interest.getName());

    if(m_unsignedNames.count(interest.getName()) != 0) {
        auto id = m_unsignedNames.at(interest.getName());
        m_unsignedNames.erase(interest.getName());
        if (m_states.count(id) != 0) {
            m_states.at(id).status = ReplyCode::FailedDependency;
        }
    }
}

void
Signer::onTimeout(const Interest& interest)
{
    NDN_LOG_ERROR("Interest Timeout on "<< interest.getName());

    if(m_unsignedNames.count(interest.getName()) != 0) {
        auto id = m_unsignedNames.at(interest.getName());
        m_unsignedNames.erase(interest.getName());
        if (m_states.count(id) != 0) {
            m_states.at(id).status = ReplyCode::FailedDependency;
        }
    }
}

Verifier::Verifier(MpsVerifier verifier, Face& face)
        : MpsVerifier(std::move(verifier)), m_face(face)
{
}

void
Verifier::setCertVerifyCallback(const function<bool(const Data&)>& func) {
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
                                   [&](auto && PH1, auto && PH2) { onData(PH1, PH2); },
                                   [&](auto && PH1, auto && PH2) { onNack(PH1, PH2); },
                                   [&](auto && PH1) { onTimeout(PH1); });
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
            m_queue.at(i).callback(false);
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
                NDN_LOG_ERROR("Certificate cannot be decoded for " << interest.getName());
            }
            addCert(interest.getName(), key);
            satisfyItem(interest.getName());
        } else {
            removeAll(interest.getName());
            NDN_LOG_ERROR("Certificate cannot be verified for " << interest.getName());
        }
    } else {
        //signer list
        data.getContent().parse();
        for (const auto& item : data.getContent().elements()) {
            if (item.type() == tlv::MpsSignerList) {
                addSignerList(interest.getName(), MpsSignerList(item));
                satisfyItem(interest.getName());
                return;
            }
        }
        removeAll(interest.getName());
        NDN_LOG_ERROR("signer list not found in " << interest.getName());
    }
}

void Verifier::satisfyItem(const Name &itemName) {
    for (auto i : m_index.at(itemName)) {
        if (m_queue.count(i) != 0) {
            if (m_queue.at(i).itemLeft == 1) {
                QueueRecord r = m_queue.at(i);
                m_queue.erase(i);
                asyncVerifySignature(r.data, r.schema, r.callback);
            } else {
                m_queue.at(i).itemLeft --;
            }
        }
    }
    m_index.erase(itemName);
}

void
Verifier::onNack(const Interest& interest, const lp::Nack& nack) {
    removeAll(interest.getName());
    NDN_LOG_ERROR("Received NACK with reason " << nack.getReason() << " for " << interest.getName());
}

void
Verifier::onTimeout(const Interest& interest) {
    removeAll(interest.getName());
    NDN_LOG_ERROR("interest time out for " << interest.getName());
}

} // namespace ndn