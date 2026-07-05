package com.apicatalog.cel.io;

import java.io.ByteArrayOutputStream;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import com.apicatalog.cel.Event;
import com.apicatalog.cel.EventEntry;
import com.apicatalog.cel.EventLog;
import com.apicatalog.cel.Operation;

import jakarta.json.stream.JsonGenerator;
import jakarta.json.stream.JsonGeneratorFactory;

public class JakartaEventLogGenerator {
    
    public static byte[] toByteArray(JsonGeneratorFactory factory, EventLog eventLog) {

        var bos = new ByteArrayOutputStream();

        try (var gen = factory.createGenerator(bos)) {
            write(gen, eventLog);
        }

        return bos.toByteArray();
    }

    public static void write(JsonGenerator gen, EventLog eventLog) {
        gen.writeStartObject()
                .writeKey("log")
                .writeStartArray();

        for (var eventEntry : eventLog.eventEntries()) {
            write(gen, eventEntry);
        }

        gen.writeEnd().writeEnd();
    }

    public static void write(JsonGenerator gen, EventEntry entry) {
        gen.writeStartObject();
        gen.writeKey("event");

        write(gen, entry.event());

        if (entry.proofs() != null && !entry.proofs().isEmpty()) {
            gen.writeKey("proof").writeStartArray();
            for (var proof : entry.proofs()) {
                gen.writeStartObject();
                for (var proofEntry : proof.entrySet()) {
                    gen.write(proofEntry.getKey(), proofEntry.getValue());
                }
                gen.writeEnd();
            }
            gen.writeEnd();
        }
        gen.writeEnd();
    }

    public static void write(JsonGenerator gen, Event event) {
        gen.writeStartObject();

        if (event.previousEventHash() != null) {
            gen.write("previousEventHash", event.previousEventHash());
        }

        gen.writeKey("operation");

        write(gen, event.operation());

        if (event.proofs() != null && !event.proofs().isEmpty()) {
            gen.writeKey("proof");
            if (event.proofs() instanceof ArrayList<Map<String, String>>) {
                gen.writeStartArray();
            }
            for (var proof : event.proofs()) {
                gen.writeStartObject();
                for (var proofEntry : proof.entrySet()) {
                    gen.write(proofEntry.getKey(), proofEntry.getValue());
                }
                gen.writeEnd();
            }
            if (event.proofs() instanceof ArrayList<Map<String, String>>) {
                gen.writeEnd();
            }
        }
        gen.writeEnd();
    }

    public static void write(JsonGenerator gen, Operation operation) {
        gen.writeStartObject();
        gen.write("type", operation.type());
        if (operation.data() != null) {
            gen.writeKey("data");
            writeValue(gen, operation.data());
        }
        gen.writeEnd();
    }

    public static void writeValue(JsonGenerator gen, Object value) {
        if (value == null) {
            gen.writeNull();
            return;
        }

        if (value instanceof Boolean bool) {
            gen.write(bool);
            return;
        }

        if (value instanceof String string) {
            gen.write(string);
            return;
        }

        if (value instanceof BigDecimal number) {
            gen.write(number);
        }

        if (value instanceof Map<?, ?> map) {
            gen.writeStartObject();
            for (var entry : map.entrySet()) {
                gen.writeKey((String) entry.getKey());
                writeValue(gen, entry.getValue());
            }
            gen.writeEnd();
            return;
        }

        if (value instanceof Collection<?> array) {
            gen.writeStartArray();
            for (var el : array) {
                writeValue(gen, el);
            }
            gen.writeEnd();
        }
    }

}
