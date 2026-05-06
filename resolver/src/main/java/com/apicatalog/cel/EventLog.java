package com.apicatalog.cel;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import com.apicatalog.cel.CelException.ErrorCode;
import com.apicatalog.cel.status.EventEntryStatus;
import com.apicatalog.cel.status.EventStatus;
import com.apicatalog.jcs.Jcs;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.multicodec.codec.MultihashCodec;
import com.apicatalog.tree.io.TreeIOException;
import com.apicatalog.tree.io.java.JavaAdapter;

public class EventLog {

    private final List<EventEntry> eventEntries;

    private Instant modified;
    private CelData document;

    public EventLog(List<EventEntry> events) {
        this.eventEntries = events;
        this.modified = null;
        this.document = null;
    }

    public EventEntry lastEventEntry() {
        return eventEntries.getLast();
    }

    public int length() {
        return eventEntries.size();
    }

    public static String methodSpecificId(Map<String, Object> document) {

        try {
            var c14n = Jcs.canonize(document, JavaAdapter.instance());

            var hash = MessageDigest.getInstance("SHA3-256").digest(c14n.getBytes(StandardCharsets.UTF_8));

            return Multibase.BASE_58_BTC.encode(
                    MultihashCodec.SHA3_256.encode(hash));

        } catch (TreeIOException e) {
            throw new IllegalArgumentException(e);

        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public CelData verify(
            String did,
            EventStatus eventStatus,
            EventVerifier eventVerifier,
            EventEntryVerifier eventEntryVerifier) throws CelException {

        if (eventEntries.isEmpty()) {
            throw new CelException(ErrorCode.NO_EVENT_ENTRIES);
        }

        String lastEventEntryDigest = null;

        Instant lastModified = null;
        CelData data = null;

        // For each eventEntry in log, verify integrity, liveness, and temporal
        // continuity
        for (var eventEntry : eventEntries) {

            // Let event be the value of eventEntry.event property
            var event = eventEntry.event();

            // If event.previousEventHash is not present or does not equal to
            // previousEventHash, then event chain is corrupted; stop processing this log
            // and continue with the next logMap entry.
            if (((lastEventEntryDigest == null
                    && event.previousEventHash() != null)
                    || (lastEventEntryDigest != null
                            && !lastEventEntryDigest.equals(event.previousEventHash())))) {
                throw new CelException(ErrorCode.BROKEN_CHAIN,
                        "Expected " + lastEventEntryDigest + ", but got " + event.previousEventHash());
            }

            // Compute the event entry digest
            var eventEntryDigest = eventEntry.digest();

            if (eventStatus != null) {

                var status = eventStatus.get(eventEntryDigest);

                if (status instanceof CelException exception) {
                    throw exception;
                }

                if (status instanceof EventEntryStatus entryStatus) {
                    lastEventEntryDigest = eventEntryDigest;
                    lastModified = entryStatus.created();
                    data = entryStatus.data();
                    continue;
                }
            }

            if (eventEntry.proofs().isEmpty()) {
                return fireError(ErrorCode.MISSING_WITNESS, eventEntryDigest, eventStatus);
            }

            if (event.proofs().isEmpty()) {
                return fireError(ErrorCode.MISSING_EVENT_PROOF, eventEntryDigest, eventStatus);
            }

            // Select the oldest event.proof.created value. Let eventCreated be the result
            var eventCreated = event.created();

            // Let operationType be the value of event.operation.type property
            var operationType = event.operation().type();

            // If operationType is the create string value
            if (Operation.CREATE_TYPE.equals(operationType)) {

                // If event.previousEventHash is present;
                // stop processing this log and continue with the next logMap entry.
                if (event.previousEventHash() != null) {
                    return fireError(ErrorCode.CORRUPTED_CHAIN,
                            lastEventEntryDigest,
                            eventStatus);
                }

                // Set didDocument to the value of event.operation.data property.
                var dataMap = event.operation().data();

                // If didDocument is not valid DID document, stop processing this log and
                // continue with the next logMap entry.
                data = CelData.of(dataMap);

                if (!data.isValidFor(did)) {
                    return fireError(ErrorCode.INVALID_DID_DOCUMENT,
                            eventEntryDigest,
                            eventStatus);
                }

                // Recreate initial DID document by removing the did:cel identifier occurrence
                // from the DID document
                var initialDocument = CelData.remove(did, dataMap);

                // Compute multihash(sha3-256(JCS(initialDidDocument))). The result value MUST
                // exactly match the initialDidDocumentHash extracted from the DID.
                if (!did.equals("did:cel:" + methodSpecificId(initialDocument))) {
                    // TODO
                    throw new CelException(ErrorCode.INVALID_GENESIS);
                }

            } else {

                // If event.previousEventHash is not present;
                // stop processing this log and continue with the next logMap entry.
                if (event.previousEventHash() == null) {
                    return fireError(ErrorCode.CORRUPTED_CHAIN,
                            lastEventEntryDigest,
                            eventStatus);
                }

                // Compute the absolute duration between eventCreated and lastModified values.
                // Let duration be the result.
                var duration = Duration.between(eventCreated, lastModified).abs();

                // If duration is greater than heartbeatFrequency, then the log is not alive;
                // stop processing this log and continue with the next logMap entry.
                if (duration.getSeconds() > data.heartbeatFrequency().getSeconds()) {
                    return fireError(ErrorCode.EVENT_TIME_GAP,
                            eventEntryDigest,
                            eventStatus);
                }

                // If operationType is not one of the string values heartbeat, update, or
                // deactivate, an unknown operationType has been detected; store
                // INVALID_OPERATION_TYPE error in eventStatus under the key eventEntryHash,
                // continue with the next logMap entry.
                if (!Operation.UPDATE_TYPE.equals(operationType)
                        && !Operation.DEACTIVATE_TYPE.equals(operationType)
                        && !Operation.HEARTBEAT_TYPE.equals(operationType)) {
                    return fireError(ErrorCode.INVALID_OPERATION,
                            eventEntryDigest,
                            eventStatus);
                }
            }

            // Let ttl be eventCreated + heartbeatFrequency.
            var ttl = eventCreated.plus(data.heartbeatFrequency());

            // Verify the event integrity. For each proof in event.proof:
//            for (var proof : event.proofs()) {
//
//                // If proof.proofPurpose is not assertionMethod string value, stop processing
//                // this log and continue with the next logMap entry.
//                if (!(proof.get("proofPurpose") instanceof String purpose)
//                        || !"assertionMethod".equals(purpose)) {
//                    return fireError(ErrorCode.INVALID_EVENT_PROOF_PURPOSE,
//                            "Expected 'assertionMethod', but got " + proof.get("proofPurpose"),
//                            eventEntryDigest,
//                            eventStatus);
//                }
//
                // If proof.created is after ttl, then the proof is invalid; stop processing
                // this log and continue with the next logMap entry.
//                if (!(proof.get("created") instanceof String created))
                // TODO

//                // If proof.verificationMethod is not present in verificationMethod [=set=];
//                // stop processing this log and continue with the next logMap entry.
//                if (data.assertionMethod() == null
//                        || data.assertionMethod().isEmpty()
//                        || !(proof.get("verificationMethod") instanceof String verification)
//                        || !data.assertionMethod().contains(verification)) {
//                    return fireError(ErrorCode.ILLEGAL_ASSERTION_METHOD, eventEntryDigest, cache);
//                }
//            }

            // Verify the event with a VC Data Integrity conformant verifier. If the
            // verification fails, then the event is not consistent; stop processing this
            // log and continue with the next logMap entry.
            eventVerifier.verify(event, data);

            // Verify the eventEntry integrity. For each proof in eventEntry.proof:
            for (var proof : eventEntry.proofs()) {

                // If proof.proofPurpose is not assertionMethod string value, stop processing
                // this log and continue with the next logMap entry.
                if (!(proof.get("proofPurpose") instanceof String purpose)
                        || !"assertionMethod".equals(purpose)) {
                    return fireError(ErrorCode.INVALID_EVENT_PROOF_PURPOSE,
                            "Expected 'assertionMethod', but got " + proof.get("proofPurpose"),
                            eventEntryDigest,
                            eventStatus);
                }

                // If proof.created is after ttl, then the proof is invalid; stop processing
                // this log and continue with the next logMap entry.
//                if (!(proof.get("created") instanceof String created))
                // TODO
            }

            // Verify the eventEntry with a VC Data Integrity conformant verifier. An
            // implementation MUST use application logic to determine the minimum number of
            // witness proofs to pass. If the verification fails, then the event entry is
            // not consistent; stop processing this log and continue with the next logMap
            // entry.
            eventEntryVerifier.verify(eventEntry);

            if (Operation.DEACTIVATE_TYPE.equals(operationType)) {
                return fireError(ErrorCode.DEACTIVATED,
                        eventEntryDigest,
                        eventStatus);
            }

            // If operationType is update string value, update verificationMethod
            if (Operation.UPDATE_TYPE.equals(operationType)) {
                // Set didDocument to the value of event.operation.data property.
                data = CelData.of(event.operation().data());

                if (!data.isValidFor(did)) {
                    return fireError(ErrorCode.INVALID_DID_DOCUMENT,
                            eventEntryDigest,
                            eventStatus);
                }
            }

            // Let lastModified be the eventCreated value.
            lastModified = eventCreated;

            // Set previousEventHash
            lastEventEntryDigest = eventEntryDigest;

            if (eventStatus != null) {
                eventStatus.set(eventEntryDigest, new EventEntryStatus(eventCreated, Instant.now(), data));
            }
        }

        // Compute the absolute duration between the current execution datetime and the
        // lastModified value. Let duration be the result.
        var duration = Duration.between(Instant.now(), lastModified).abs();

        // If duration is greater than heartbeatFrequency, then the log is not alive;
        // stop processing this log and continue with the next logMap entry.
        if (duration.getSeconds() > data.heartbeatFrequency().getSeconds()) {
            throw new CelException(ErrorCode.ABANDONED);
        }

        // If the endpoint is not listed as a CelStorageService endpoint in the
        // didDocument service section, then the log origin is not approved; stop
        // processing this log and continue with the next logMap entry.
        // TODO

        // Update event log instance metadata
        this.modified = lastModified;
        this.document = data;

        // Return a didDocument as the read algorithm result.
        return data;
    }

    public CelData document() {
        return document;
    }

    public Instant modified() {
        return modified;
    }

    private static CelData fireError(
            ErrorCode code,
            String statusKey,
            EventStatus cache) throws CelException {
        return fireError(new CelException(code), statusKey, cache);
    }

    private static CelData fireError(ErrorCode code,
            String message,
            String statusKey,
            EventStatus cache) throws CelException {
        return fireError(new CelException(code, message), statusKey, cache);
    }

    private static CelData fireError(
            CelException ex,
            String statusKey,
            EventStatus cache) throws CelException {
        cache.set(statusKey, ex);
        throw ex;
    }

    public List<EventEntry> eventEntries() {
        return eventEntries;
    }

}
