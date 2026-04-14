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

    public Map<String, Object> verifyInception(String did) {
        if (!did.startsWith("did:cel:")) {
            // TODO
            throw new IllegalArgumentException(did);
        }

        var msid = did.substring("did:cel:".length());

        // Extract the create event log entry
        var createEventEntry = eventEntries.getFirst();
        var createEvent = createEventEntry.event();

        if (!"create".equals(createEvent.operation().type())) {
            // TODO
            throw new IllegalArgumentException();
        }

        // Extract DID document from the create event
        var document = createEvent.operation().data();

        IO.println(document);

        // Parse and validate the DID document
        var didDocument = DidDocument.of(document);

        // The didDocument.id and didDocument.assertionMethod.controller fields MUST
        // exactly match the did:cel which is being resolved.
        if (!did.equals(didDocument.id())) {
            // TODO
            throw new IllegalArgumentException();
        }

        if (didDocument.assertion() == null
                || !did.equals(didDocument.assertion().controller())) {
            // TODO
//            throw new IllegalArgumentException();
        }

        // Recreate initial DID document by removing the did:cel identifier occurrence
        // from the DID document
        var initialDocument = DidDocument.remove(did, document);

        // Compute multihash(sha3-256(JCS(initialDidDocument))). The result value MUST
        // exactly match the initialDidDocumentHash extracted from the DID.
        if (!msid.equals(methodSpecificId(initialDocument))) {
            // TODO
            throw new IllegalArgumentException();
        }

        // Verify create event integrity

        // The create event is signed by a key authorized in the assertionMethod
        // declaration
        var proofs = createEvent.proofs();
        // TODO

        // Verify create event entry integrity

        // Witness Verification: The resolver MUST verify that the event contains a
        // sufficient number of valid witness signatures. The specific threshold and
        // selection of required witnesses are determined by application-level logic
        // based on the trust requirements of the relying party
        createEventEntry.proofs();
        // TODO

        // Get multibase encoded digest for the create event to witness
        final var digestMultibase = createEventEntry.digestToWitness();

        return document;
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

    public Map<String, Object> verify(String did) throws CelException {

        // Set logState to active string value.
        var active = true;

        Duration heartbeatFrequency = null;
        String previousEventHash = null;
        Instant lastModified = null;

        Map<String, Object> document = null;

        // For each eventEntry in log, verify integrity, liveness, and temporal
        // continuity
        for (var eventEntry : eventEntries) {

            // Let event be the value of eventEntry.event property
            var event = eventEntry.event();

            // Select the oldest event.proof.created value. Let eventCreated be the result
            var eventCreated = event.created();

            // Let operationType be the value of event.operation.type property
            var operationType = event.operation().type();

            IO.println("event " + operationType + ", " + eventCreated);

            // If operationType is the create string value
            if ("create".equals(operationType)) {
                // If it's not the very first eventEntry in the log, then the log is corrupted;
                // stop processing this log and continue with the next logMap entry.
                if (previousEventHash != null) {
                    throw new IllegalArgumentException();
                }

                // Set didDocument to the value of event.operation.data property.
                document = event.operation().data();

                // If didDocument is not valid DID document, stop processing this log and
                // continue with the next logMap entry.
                // TODO

                // If didDocument.id is not did, stop processing this log and continue with the
                // next logMap entry.
                // TODO

                // Set heartbeatFrequency to the value of didDocument.heartbeatFrequency which
                // MUST conform to ISO 8601 duration format.
//                IO.println((String) document.get("heartbeatFrequency"));
//FIXME                heartbeatFrequency = Duration.parse((String) document.get("heartbeatFrequency"));
                heartbeatFrequency = Duration.parse("P14D");

            } else {

                // If event.previousEventHash is not present or does not equal to
                // previousEventHash, then event chain is corrupted; stop processing this log
                // and continue with the next logMap entry.
                if (event.previousEventHash() == null
                        || !event.previousEventHash().equals(previousEventHash)) {
                    throw new CelException(ErrorCode.BROKEN_CHAIN, "Expected " + previousEventHash + ", but got " + event.previousEventHash());
                }

                // Compute the absolute duration between eventCreated and lastModified values.
                // Let duration be the result.
                var duration = Duration.between(eventCreated, lastModified).abs();

                // If duration is greater than heartbeatFrequency, then the log is not alive;
                // stop processing this log and continue with the next logMap entry.
                if (duration.getSeconds() > heartbeatFrequency.getSeconds()) {
                    throw new IllegalArgumentException();
                }

                // If operationType is the update string value:
                if ("update".equals(operationType)) {

                    // Set didDocument to the value of event.operation.data property.
                    document = event.operation().data();

                    // Set heartbeatFrequency to the value of didDocument.heartbeatFrequency which
                    // MUST conform to ISO 8601 duration format.
                    heartbeatFrequency = Duration.parse((String) document.get("heartbeatFrequency"));

                    // Otherwise, if operationType is the deactivate string value, then set logState
                    // to the deactivated string value.
                } else if ("deactivate".equals(operationType)) {

                    active = false;
                    
                    // Otherwise, if operationType is not the heartbeat string value, then an
                    // unknown operationType has been detected; stop processing this log and
                    // continue with the next logMap entry.
                } else if (!"heartbeat".equals(operationType)) {
                    throw new IllegalArgumentException();
                }
            }
            // Let lastModified be the eventCreated value.
            lastModified = eventCreated;

            // Set previousEventHash
            previousEventHash = eventEntry.digest();
        }

        // Compute the absolute duration between the current execution datetime and the
        // lastModified value. Let duration be the result.
        var duration = Duration.between(Instant.now(), lastModified).abs();

        // If duration is greater than heartbeatFrequency, then the log is not alive;
        // stop processing this log and continue with the next logMap entry.
        if (duration.getSeconds() > heartbeatFrequency.getSeconds()) {
            throw new CelException(ErrorCode.ABANDONED);
        }

        // If the endpoint is not listed as a CelStorageService endpoint in the
        // didDocument service section, then the log origin is not approved; stop
        // processing this log and continue with the next logMap entry.
        // TODO

        // Return a map containing logState, and didDocument as the read
        // algorithm result.
        return document;
    }

}
