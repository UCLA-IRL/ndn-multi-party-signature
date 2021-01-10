#include "ndnmps/players.hpp"
#include "ndn-cxx/util/logger.hpp"
#include "ndn-cxx/util/random.hpp"

#include <utility>

namespace ndn {

NDN_LOG_INIT(ndnmps.players);

const time::milliseconds INTEREST_TIMEOUT = time::seconds(4);
const time::milliseconds ESTIMATE_PROCESS_TIME = time::seconds(1);

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
    fetchInterest.setInterestLifetime(INTEREST_TIMEOUT);
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
        block.push_back(makeNonNegativeIntegerBlock(tlv::ResultAfter, ESTIMATE_PROCESS_TIME.count()));
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
            if (!unsignedData.getSignatureInfo()) {
                NDN_LOG_ERROR("Unsigned Data does not have encoding");
                code = ReplyCode::BadRequest;
            }
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
    state.value = getSignature(unsignedData);
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
Verifier::asyncVerifySignature(shared_ptr<const Data> data, shared_ptr<const MultipartySchema> schema, const VerifyFinishCallback& callback)
{
    if (readyToVerify(*data)) {
        callback(verifySignature(*data, *schema));
    } else {
        //store, fetch and wait
        VerificationRecord r{data, schema, callback, 0};
        for (const auto& item : itemsToFetch(*data)) {
            Interest interest(item);
            interest.setCanBePrefix(false);
            interest.setMustBeFresh(true);
            interest.setInterestLifetime(INTEREST_TIMEOUT);
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
                VerificationRecord r = m_queue.at(i);
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

Initiator::Initiator(MpsVerifier& verifier, const Name& prefix, Face& face, Scheduler& scheduler)
        : m_verifier(verifier),
        m_prefix(prefix),
        m_face(face), m_scheduler(scheduler), m_lastId(0)
{
    m_handle = m_face.setInterestFilter(m_prefix, [&](auto &&, auto && PH2) { onWrapperFetch(PH2); }, nullptr,
                             Initiator::onRegisterFail);
}

Initiator::InitiationRecord::InitiationRecord(const MultipartySchema& trySchema, std::shared_ptr<Data> data,
                 const SignatureFinishCallback& successCb, const SignatureFailureCallback& failureCb)
                 : schema(trySchema), unsignedData(std::move(data)), onSuccess(successCb), onFailure(failureCb) {}

Initiator::~Initiator()
{
    m_handle->unregister();
}
void
Initiator::addSigner(const Name& keyName,const Name& prefix) {
    if (!m_verifier.getCerts().count(keyName)) {
        NDN_LOG_ERROR("do not know private key for" << keyName);
        NDN_THROW(std::runtime_error("do not know private key for" + keyName.toUri()));
    }
    m_keyToPrefix.emplace(keyName, prefix);
}

void
Initiator::setInterestSignCallback(std::function<void(Interest&)> func)
{
    m_interestSigningCallback = std::move(func);
}

void
Initiator::addSigner(const Name& keyName, const blsPublicKey& keyValue, const Name& prefix) {
    if (!m_verifier.getCerts().count(keyName)) {
        m_verifier.addCert(keyName, keyValue);
    }
    m_keyToPrefix.emplace(keyName, prefix);
}

void
Initiator::multiPartySign(const MultipartySchema& schema, std::shared_ptr<Data> unfinishedData,
               const SignatureFinishCallback& successCb, const SignatureFailureCallback& failureCb)
{
    //verify schema can be done
    std::vector<Name> keyToCheck;
    for (const auto& i : m_keyToPrefix) {
        if (!schema.getKeyMatches(i.first).empty()) {
            keyToCheck.emplace_back(i.first);
        }
    }
    if (keyToCheck.size() < schema.minOptionalSigners + schema.signers.size() ||
            !schema.getMinSigners(keyToCheck).has_value()) {
        NDN_LOG_WARN("Not enough available signers to satisfy schema");
        if (failureCb) failureCb("Not enough available signers to satisfy schema");
        return;
    }


    //register
    m_records.emplace(m_lastId, InitiationRecord(schema, unfinishedData, successCb, failureCb));
    auto& currentRecord = m_records.at(m_lastId);
    int currentId = m_lastId;
    m_lastId ++;

    //build signature info packet
    std::array<uint8_t, 8> wrapperBuf = {};
    random::generateSecureBytes(wrapperBuf.data(), 8);
    currentRecord.unsignedData->setSignatureInfo(
            SignatureInfo(static_cast<tlv::SignatureTypeValue>(tlv::SignatureSha256WithBls),
            KeyLocator(Name(m_prefix).append("mps").append("signers")
            .append(toHex(wrapperBuf.data(), 8)))));

    //wrapper
    currentRecord.wrapper.setName(Name(m_prefix).append("mps").append("wrapper").append(toHex(wrapperBuf.data(), 8)));
    currentRecord.wrapper.setContent(makeNestedBlock(tlv::Content, *currentRecord.unsignedData));
    auto wrapperFullName = currentRecord.wrapper.getFullName();
    m_wrapToId.emplace(wrapperFullName, currentId);

    //send interest
    if (!m_interestSigningCallback) {
        NDN_LOG_WARN("No signing callback for initiator");
        if (failureCb) failureCb("No signing callback for initiator");
        return;
    }
    for (const Name& i : keyToCheck) {
        Interest interest;
        interest.setName(Name(m_keyToPrefix.at(i)).append("mps").append("sign"));
        Block appParam(tlv::ApplicationParameters);
        appParam.push_back(makeNestedBlock(tlv::UnsignedWrapperName, wrapperFullName));
        interest.setApplicationParameters(appParam);
        m_interestSigningCallback(interest);
        interest.setCanBePrefix(false);
        interest.setMustBeFresh(true);
        interest.setInterestLifetime(INTEREST_TIMEOUT);
        m_face.expressInterest(interest,
                               [&, currentId, i](auto && PH1, auto && PH2) { onData(currentId, i, PH1, PH2); },
                               [&, currentId](auto && PH1, auto && PH2) { onNack(currentId, PH1, PH2); },
                               [&, currentId](auto && PH1) { onTimeout(currentId, PH1); });
    }

    NDN_LOG_WARN("Sent all interest to initiate sign");
    currentRecord.eventId = m_scheduler.schedule(INTEREST_TIMEOUT + ESTIMATE_PROCESS_TIME + INTEREST_TIMEOUT,
                                                 [&, currentId]{onSignTimeout(currentId);});
}

void
Initiator::onWrapperFetch(const Interest& interest)
{
    if (m_wrapToId.count(interest.getName())) {
        int id = m_wrapToId.at(interest.getName());
        if (m_records.count(id)) {
            m_face.put(m_records.at(id).wrapper);
        } else {
            NDN_LOG_WARN("Unexpected wrapper " << interest);
            m_face.put(lp::Nack(interest));
        }
    } else {
        NDN_LOG_WARN("Unexpected wrapper " << interest);
        m_face.put(lp::Nack(interest));
    }
}

void
Initiator::onData(int id, const Name& keyName, const Interest&, const Data& data)
{
    if (m_records.count(id) == 0) return;
    const auto& content = data.getContent();
    content.parse();
    const auto& statusBlock = content.get(tlv::Status);
    if (!statusBlock.isValid()) {
        NDN_LOG_ERROR("Signer replied data with no status" << "For interest " << data.getName());
        return;
    }
    ReplyCode status = static_cast<ReplyCode>(stoi(readString(statusBlock)));
    if (status == ReplyCode::Processing) {
        // schedule another pull
        time::milliseconds result_ms = ESTIMATE_PROCESS_TIME + ESTIMATE_PROCESS_TIME / 5;
        const auto& resultAfterBlock = content.get(tlv::ResultAfter);
        if (resultAfterBlock.isValid()) {
            result_ms = time::milliseconds(readNonNegativeInteger(resultAfterBlock));
        }
        const auto& resultAtBlock = content.get(tlv::ResultName);
        Name resultName;
        if (!resultAtBlock.isValid()) {
            NDN_LOG_ERROR("Signer processing but no result name replied: data for" << data.getName());
            return;
        } else {
            try {
                resultName = Name(resultAtBlock.blockFromValue());
            } catch (const std::exception& e) {
                NDN_LOG_ERROR("Signer processing but bad result name replied: data for" << data.getName());
                return;
            }
        }
        m_scheduler.schedule(result_ms, [&]{
            Interest interest;
            interest.setName(resultName);
            interest.setCanBePrefix(false);
            interest.setMustBeFresh(true);
            interest.setInterestLifetime(INTEREST_TIMEOUT);
            m_face.expressInterest(interest,
                                   [&, id, keyName](auto && PH1, auto && PH2) { onData(id, keyName, PH1, PH2); },
                                   [&, id](auto && PH1, auto && PH2) { onNack(id, PH1, PH2); },
                                   [&, id](auto && PH1) { onTimeout(id, PH1); });
        });
    } else if (status == ReplyCode::OK) {
        // add to record, may call success

        const Block& b = content.get(tlv::SignatureValue);
        if (!b.isValid()) {
            NDN_LOG_ERROR("Signer OK but bad signature value decoding failed: data for" << data.getName());
            return;
        }
        blsSignature sig;
        int re = blsSignatureDeserialize(&sig, b.value(), b.value_size());
        if (re == 0) {
            NDN_LOG_ERROR("Signer OK but bad signature value decoding failed: data for" << data.getName());
            return;
        }

        auto& record = m_records.at(id);
        m_verifier.verifySignaturePiece(*record.unsignedData, keyName, b);
        record.signaturePieces.emplace(keyName, sig);
        if (record.signaturePieces.size() >= record.schema.signers.size() + record.schema.minOptionalSigners) {
            std::vector<Name> successPiece(record.signaturePieces.size());
            for (const auto &i : record.signaturePieces) {
                successPiece.emplace_back(i.first);
            }
            if (record.schema.getMinSigners(successPiece).has_value()) {
                //success
                successCleanup(id);
            }
        }
    } else {
        NDN_LOG_ERROR("Signer replied status: " << static_cast<int>(status) << "For interest " << data.getName());
        return;
    }
}

void
Initiator::onNack(int id, const Interest& interest, const lp::Nack& nack)
{
    NDN_LOG_ERROR("NACK on interest " << interest.getName() << "For id "<< id << " With reason " << nack.getReason());
}

void
Initiator::onTimeout(int id, const Interest& interest)
{
    NDN_LOG_ERROR("Timeout on interest " << interest.getName() << "For id "<< id);
}

void
Initiator::onRegisterFail(const Name& prefix, const std::string& reason){
    NDN_LOG_ERROR("Fail to register prefix " << prefix.toUri() << " because " << reason);
}

void
Initiator::onSignTimeout(int id){
    if (m_records.count(id) == 0) return;
    auto record = m_records.at(id);
    std::vector<Name> successPiece(record.signaturePieces.size());
    for (const auto& i : record.signaturePieces) {
        successPiece.emplace_back(i.first);
    }
    if (record.schema.getMinSigners(successPiece).has_value()) {
        //success
        successCleanup(id);
    } else {
        //failure
        record.onFailure(std::string("Insufficient signature piece at timeout; collected ") +
                        std::to_string(successPiece.size()) + std::string(" Pieces"));
        NDN_LOG_ERROR("Insufficient signature piece at timeout; collected "<< successPiece.size() << " Pieces");
    }

    m_wrapToId.erase(record.wrapper.getFullName());
    m_records.erase(id);
}

void
Initiator::successCleanup(int id)
{
    if (m_records.count(id) == 0) return;
    const auto& record = m_records.at(id);

    std::vector<Name> successPiece(record.signaturePieces.size());
    std::vector<blsSignature> pieces(record.signaturePieces.size());
    for (const auto& i : record.signaturePieces) {
        successPiece.emplace_back(i.first);
        pieces.emplace_back(i.second);
    }

    MpsSignerList signerList(successPiece);
    Data signerListData;
    signerListData.setName(record.unsignedData->getSignatureInfo().getKeyLocator().getName());
    signerListData.setContent(makeNestedBlock(tlv::Content, signerList));
    //TODO sign?

    buildMultiSignature(*record.unsignedData, pieces);

    if (record.onSuccess) {
        record.onSuccess(record.unsignedData, std::move(signerListData));
    }

    m_wrapToId.erase(record.wrapper.getFullName());
    m_records.erase(id);
}

} // namespace ndn