package com.apicatalog.cel;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.apicatalog.cel.CelException.ErrorCode;
import com.apicatalog.cel.cache.EventEntryStatus;
import com.apicatalog.cel.cache.StatusCache;
import com.apicatalog.jcs.Jcs;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.multicodec.codec.MultihashCodec;
import com.apicatalog.tree.io.TreeIOException;
import com.apicatalog.tree.io.java.JavaAdapter;

import jakarta.json.stream.JsonGenerator;
import jakarta.json.stream.JsonGeneratorFactory;
import jakarta.json.stream.JsonParser;

public class EventLog {

    private final List<EventEntry> eventEntries;

    public EventLog(List<EventEntry> events) {
        this.eventEntries = events;
    }

    public static final EventLog read(JsonParser parser) {

        if (!parser.hasNext() || parser.next() != JsonParser.Event.START_OBJECT) {
            throw new IllegalArgumentException("Event log body must be a JSON object.");
        }

        final var events = new ArrayList<EventEntry>();

        while (parser.hasNext()) {

            var next = parser.next();

            if (next == JsonParser.Event.END_OBJECT) {
                break;
            }

            switch (parser.getString()) {
            case "log":
                if (parser.next() != JsonParser.Event.START_ARRAY) {
                    throw new IllegalArgumentException("Event log entry must be an array event");
                }

                while (parser.hasNext()) {
                    var parserEvent = parser.next();

                    if (parserEvent == JsonParser.Event.END_ARRAY) {
                        break;
                    }
                    events.add(EventEntry.read(parser, parserEvent));
                }
                break;

            case String unknown:
                throw new IllegalArgumentException(
                        "An unknown request property '%s' has been detected".formatted(unknown));
            }
        }

        return new EventLog(events);
    }

    public EventEntry lastEventEntry() {
        return eventEntries.getLast();
    }

    public int size() {
        return eventEntries.size();
    }

    public byte[] toByteArray(JsonGeneratorFactory factory) {

        var bos = new ByteArrayOutputStream();

        try (var gen = factory.createGenerator(bos)) {
            write(gen);
        }

        return bos.toByteArray();
    }

    public void write(JsonGenerator gen) {
        gen.writeStartObject()
                .writeKey("log")
                .writeStartArray();

        for (var event : eventEntries) {
            event.write(gen);
        }

        gen.writeEnd().writeEnd();
    }

    public int length() {
        return eventEntries.size();
    }

//    public Map<String, Object> verifyInception(String did) {
//        if (!did.startsWith("did:cel:")) {
//            // TODO
//            throw new IllegalArgumentException(did);
//        }
//
//        var msid = did.substring("did:cel:".length());
//
//        // Extract the create event log entry
//        var createEventEntry = eventEntries.getFirst();
//        var createEvent = createEventEntry.event();
//
//        if (!"create".equals(createEvent.operation().type())) {
//            // TODO
//            throw new IllegalArgumentException();
//        }
//
//        // Extract DID document from the create event
//        var document = createEvent.operation().data();
//
//        IO.println(document);
//
//        // Parse and validate the DID document
//        var didDocument = DidDocument.of(document);
//
//        // The didDocument.id and didDocument.assertionMethod.controller fields MUST
//        // exactly match the did:cel which is being resolved.
//        if (!did.equals(didDocument.id())) {
//            // TODO
//            throw new IllegalArgumentException();
//        }
//
//        if (didDocument.assertion() == null
//                || !did.equals(didDocument.assertion().controller())) {
//            // TODO
    //// throw new IllegalArgumentException();
//        }
//
//        // Recreate initial DID document by removing the did:cel identifier occurrence
//        // from the DID document
//        var initialDocument = CelData.remove(did, document);
//
//        // Compute multihash(sha3-256(JCS(initialDidDocument))). The result value MUST
//        // exactly match the initialDidDocumentHash extracted from the DID.
//        if (!msid.equals(methodSpecificId(initialDocument))) {
//            // TODO
//            throw new IllegalArgumentException();
//        }
//
//        // Verify create event integrity
//
//        // The create event is signed by a key authorized in the assertionMethod
//        // declaration
//        var proofs = createEvent.proofs();
//        // TODO
//
//        // Verify create event entry integrity
//
//        // Witness Verification: The resolver MUST verify that the event contains a
//        // sufficient number of valid witness signatures. The specific threshold and
//        // selection of required witnesses are determined by application-level logic
//        // based on the trust requirements of the relying party
//        createEventEntry.proofs();
//        // TODO
//
//        // Get multibase encoded digest for the create event to witness
//        final var digestMultibase = createEventEntry.digestToWitness();
//
//        return document;
//    }

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
            StatusCache cache,
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

            // Compute the event entry digest
            var eventEntryDigest = eventEntry.digest();

            if (cache != null) {
                var status = cache.get(eventEntryDigest);

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
                return fireError(ErrorCode.MISSING_WITNESS, eventEntryDigest, cache);
            }

            // Let event be the value of eventEntry.event property
            var event = eventEntry.event();

            if (event.proofs().isEmpty()) {
                return fireError(ErrorCode.MISSING_EVENT_PROOF, eventEntryDigest, cache);
            }

            // Select the oldest event.proof.created value. Let eventCreated be the result
            var eventCreated = event.created();

            // Let operationType be the value of event.operation.type property
            var operationType = event.operation().type();

            // If operationType is the create string value
            if (Operation.CREATE_TYPE.equals(operationType)) {
                // If it's not the very first eventEntry in the log, then the log is corrupted;
                // stop processing this log and continue with the next logMap entry.
                if (lastEventEntryDigest != null) {
                    return fireError(ErrorCode.CORRUPTED_CHAIN, eventEntryDigest, cache);
                }

                // Set didDocument to the value of event.operation.data property.
                var dataMap = event.operation().data();

                // If didDocument is not valid DID document, stop processing this log and
                // continue with the next logMap entry.
                data = CelData.of(dataMap);

                if (!data.isValidFor(did)) {
                    return fireError(ErrorCode.INVALID_DID_DOCUMENT, eventEntryDigest, cache);
                }

//                // Set assertionMethod to a [=set=] initialized with
//                // didDocument.assertionMethod property value
//                verificationMethod = data.assertionMethod();

            } else {

                // If event.previousEventHash is not present or does not equal to
                // previousEventHash, then event chain is corrupted; stop processing this log
                // and continue with the next logMap entry.
                if (event.previousEventHash() == null
                        || !event.previousEventHash().equals(lastEventEntryDigest)) {
                    return fireError(ErrorCode.BROKEN_CHAIN,
                            "Expected " + lastEventEntryDigest + ", but got " + event.previousEventHash(),
                            eventEntryDigest,
                            cache);
                }

                // Compute the absolute duration between eventCreated and lastModified values.
                // Let duration be the result.
                var duration = Duration.between(eventCreated, lastModified).abs();

                // If duration is greater than heartbeatFrequency, then the log is not alive;
                // stop processing this log and continue with the next logMap entry.
                if (duration.getSeconds() > data.heartbeatFrequency().getSeconds()) {
                    return fireError(ErrorCode.EVENT_TIME_GAP, eventEntryDigest, cache);
                }

                // If operationType is not one of the string values heartbeat, update, or
                // deactivate, an unknown operationType has been detected; store
                // INVALID_OPERATION_TYPE error in eventStatus under the key eventEntryHash,
                // continue with the next logMap entry.
                if (!Operation.UPDATE_TYPE.equals(operationType)
                        && !Operation.DEACTIVATE_TYPE.equals(operationType)
                        && !Operation.HEARTBEAT_TYPE.equals(operationType)) {
                    return fireError(ErrorCode.INVALID_OPERATION, eventEntryDigest, cache);
                }
            }

            // Let ttl be eventCreated + heartbeatFrequency.
            var ttl = eventCreated.plus(data.heartbeatFrequency());

            // Verify the event integrity. For each proof in event.proof:
            for (var proof : event.proofs()) {

                // If proof.proofPurpose is not assertionMethod string value, stop processing
                // this log and continue with the next logMap entry.
                if (!(proof.get("proofPurpose") instanceof String purpose)
                        || !"assertionMethod".equals(purpose)) {
                    return fireError(ErrorCode.INVALID_EVENT_PROOF_PURPOSE,
                            "Expected 'assertionMethod', but got " + proof.get("proofPurpose"),
                            eventEntryDigest,
                            cache);
                }

                // If proof.controller is not did, stop processing this log and continue with
                // the next logMap entry.
                if (!(proof.get("controller") instanceof String controller)
                        || !did.equals(controller)) {
                    return fireError(ErrorCode.INVALID_EVENT_PROOF_CONTROLLER, eventEntryDigest, cache);
                }

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
            }

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
                            cache);
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
                return fireError(ErrorCode.DEACTIVATED, eventEntryDigest, cache);
            }

            // If operationType is update string value, update verificationMethod
            if (Operation.UPDATE_TYPE.equals(operationType)) {
                // Set didDocument to the value of event.operation.data property.
                data = CelData.of(event.operation().data());

                if (!data.isValidFor(did)) {
                    return fireError(ErrorCode.INVALID_DID_DOCUMENT, eventEntryDigest, cache);
                }
            }

            // Let lastModified be the eventCreated value.
            lastModified = eventCreated;

            // Set previousEventHash
            lastEventEntryDigest = eventEntryDigest;

            if (cache != null) {
                cache.set(eventEntryDigest, new EventEntryStatus(eventCreated, data));
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

        // Return a didDocument as the read algorithm result.
        return data;
    }

    private static CelData fireError(
            ErrorCode code,
            String eventEntryDigest,
            StatusCache cache) throws CelException {
        return fireError(new CelException(code), eventEntryDigest, cache);
    }

    private static CelData fireError(ErrorCode code,
            String message,
            String eventEntryDigest,
            StatusCache cache) throws CelException {
        return fireError(new CelException(code, message), eventEntryDigest, cache);
    }

    private static CelData fireError(
            CelException ex,
            String eventEntryDigest,
            StatusCache cache) throws CelException {
        cache.set(eventEntryDigest, ex);
        throw ex;
    }

}
