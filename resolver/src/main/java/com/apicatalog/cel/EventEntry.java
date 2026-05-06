package com.apicatalog.cel;

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

public class EventEntry {

    private Event event;
    private List<Map<String, String>> proofs;

    public EventEntry(Event event, List<Map<String, String>> proofs) {
        this.event = event;
        this.proofs = proofs;
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

    public void addProof(Map<String, String> witnessProof) {
        if (proofs == null) {
            proofs = List.of(witnessProof);
            return;
        }

        if (proofs instanceof ArrayList<Map<String, String>> list) {
            list.add(witnessProof);
            return;
        }

        proofs = new ArrayList<>(proofs);
        proofs.add(witnessProof);
    }

    public void write(JsonGenerator gen) {
        gen.writeStartObject();
        gen.writeKey("event");
        event.write(gen);
        if (proofs != null && !proofs.isEmpty()) {
            gen.writeKey("proof").writeStartArray();
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

    public Event event() {
        return event;
    }

    public List<Map<String, String>> proofs() {
        return proofs;
    }

    public String digest() {

        try {
            var c14Event = new ByteArrayOutputStream();
            var writer = new OutputStreamWriter(c14Event, StandardCharsets.UTF_8);

            writer.write("{\"event\":{\"operation\":{");
            if (event.operation().data() != null) {
                writer.write("\"data\":");
                Jcs.canonize(event.operation().data(), writer);
                writer.write(",");
            }
            writer.write("\"type\":\"");
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
            writer.write("}");
            if (proofs != null && !proofs.isEmpty()) {
                writer.write(",\"proof\":");
                if (proofs.size() > 1
                        || (event.proofs() instanceof ArrayList)) {
                    Jcs.canonize(proofs, JavaAdapter.instance(), writer);

                } else {
                    Jcs.canonize(proofs.getFirst(), JavaAdapter.instance(), writer);
                }
            }
            writer.write("}");
            writer.flush();
            
            var c14Bytes = c14Event.toByteArray();
            
//            IO.println(new String(c14Bytes));

            return Multibase.BASE_58_BTC.encode(
                    MultihashCodec.SHA3_256.encode(
                            MessageDigest.getInstance("SHA3-256")
                                    .digest(c14Bytes)));

        } catch (NoSuchAlgorithmException | IOException | TreeIOException e) {
            throw new IllegalStateException(e);
        }
    }
}
