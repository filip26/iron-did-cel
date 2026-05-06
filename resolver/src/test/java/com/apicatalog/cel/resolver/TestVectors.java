package com.apicatalog.cel.resolver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.apicatalog.cel.CelData;
import com.apicatalog.cel.Event;
import com.apicatalog.cel.EventEntry;
import com.apicatalog.cel.EventLog;
import com.apicatalog.cel.Operation;
import com.apicatalog.cel.io.JakartaEventLogReader;

import jakarta.json.Json;

class TestVectors {

    @Test
    void testInception() {

        try (final var parser = Json.createParser(getClass().getResourceAsStream("initial-document-1.json"))) {

            var document = JakartaEventLogReader.parseData(parser);

            assertNotNull(document);

            var genesis = CelData.remove("did:cel:zW1p8gNTf4eQKGpsGhq57cwji1wqhaXMYZZwCneJX6fgGR2", document);

            final var methodSpecificId = EventLog.methodSpecificId(genesis);

            assertEquals("zW1p8gNTf4eQKGpsGhq57cwji1wqhaXMYZZwCneJX6fgGR2", methodSpecificId);
        }
    }
    
    @Test
    void testCreateEntry() throws IOException {

        try (final var parser = Json.createParser(getClass().getResourceAsStream("initial-document-1.json"))) {

            var document = JakartaEventLogReader.parseData(parser);

            assertNotNull(document);

            var data = CelData.of(document);
            
            assertEquals("did:cel:zW1p8gNTf4eQKGpsGhq57cwji1wqhaXMYZZwCneJX6fgGR2", data.id());
            
            var op = new Operation(Operation.CREATE_TYPE, document);
            var event = new Event(null, op, List.of());
            var entry = new EventEntry(event, List.of());
            var os = new ByteArrayOutputStream();
            
            var gen = Json.createGenerator(os);
            
            event.write(gen);
            
            gen.close();
            
            IO.println(os.toString());
        }

    }

}
