import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.apicatalog.jcs.Jcs;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.multicodec.codec.MultihashCodec;
import com.apicatalog.tree.io.TreeIOException;
import com.apicatalog.tree.io.java.JavaAdapter;

import jakarta.json.stream.JsonGenerator;
import jakarta.json.stream.JsonParser;

class EventEntry {

    private Event event;
    private List<Map<String, String>> proofs;

    public EventEntry(Event event, List<Map<String, String>> proofs) {
        this.event = event;
        this.proofs = proofs;
    }

    public static EventEntry read(JsonParser parser) {
        if (!parser.hasNext() || parser.next() != JsonParser.Event.START_OBJECT) {
            throw new IllegalArgumentException("Event must be a JSON object.");
        }

        Event event = null;
        List<Map<String, String>> proofs = null;

        while (parser.hasNext()) {

            var next = parser.next();

            if (next == JsonParser.Event.END_OBJECT) {
                break;
            }

            switch (parser.getString()) {
            case "event":
                if (parser.next() != JsonParser.Event.START_OBJECT) {
                    throw new IllegalArgumentException("Event operation must be array");
                }

                while (parser.hasNext()) {
                    if (parser.next() == JsonParser.Event.END_OBJECT) {
                        break;
                    }
                    event = Event.read(parser);
                }
                break;

            case "proof":
                proofs = Proof.read(parser);
                break;

            case String unknown:
                throw new IllegalArgumentException(
                        "An unknown request property '%s' has been detected".formatted(unknown));
            }
        }

        if (event == null) {
            throw new IllegalArgumentException("Event entry does not contain an event object");
        }

        return new EventEntry(event, proofs.isEmpty() ? null : proofs);
    }

    public String digestToWitness() {

        try {
            var c14Event = new ByteArrayOutputStream();
            var writer = new OutputStreamWriter(c14Event, StandardCharsets.UTF_8);

            writer.write("{\"event\":{\"operation\":{");
            writer.write("\"data\":");
            Jcs.canonize(event.operation().data(), writer);
            writer.write(",\"type\":\"");
            writer.write(event.operation().type());
            writer.write("\"}");
            if (event.previousEventHash() != null) {
                writer.write(",\"previousEventHash\":\"");
                writer.write(event.previousEventHash());
                writer.write("\"");
            }
            writer.write(",\"proof\":");

            if (event.proofs().size() > 1
                    || (event.proofs() instanceof ArrayList)) {
                Jcs.canonize(event.proofs(), JavaAdapter.instance(), writer);
            } else {
                Jcs.canonize(event.proofs().getFirst(), JavaAdapter.instance(), writer);
            }

            Jcs.canonize(event.proofs(), JavaAdapter.instance(), writer);
            writer.write("}}");
            writer.flush();

            return Multibase.BASE_58_BTC.encode(
                    MultihashCodec.SHA3_256.encode(
                            MessageDigest.getInstance("SHA3-256")
                                    .digest(c14Event.toByteArray())));

        } catch (NoSuchAlgorithmException | IOException | TreeIOException e) {
            throw new IllegalStateException(e);
        }
    }

    public void addProof(List<Map<String, String>> witnessProofs) {
        if (proofs == null) {
            proofs = List.copyOf(witnessProofs);
            return;
        }
        if (proofs instanceof ArrayList<Map<String, String>> list) {
            list.addAll(witnessProofs);
            return;
        }

        proofs = new ArrayList<>(proofs);
        proofs.addAll(witnessProofs);
    }

    public void write(JsonGenerator gen) {
        gen.writeStartObject();
        gen.write("event");
        event.write(gen);
        if (proofs != null && !proofs.isEmpty()) {
            gen.write("proof").writeStartArray();
            for (var proof : proofs) {
                gen.writeStartObject();
                for (var entry : proof.entrySet()) {
                    gen.write(entry.getKey(), entry.getValue());
                }
                gen.writeEnd();
            }
            gen.writeEnd();
        }
        gen.writeEnd();
    }
}
