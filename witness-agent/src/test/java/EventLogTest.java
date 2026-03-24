import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.StringWriter;

import org.junit.jupiter.api.Test;

import jakarta.json.Json;

class EventLogTest {

    @Test
    void testRead() { // TODO parameterize, more test cases

        var input = getClass().getResourceAsStream("log-1.json");

        try (var parser = Json.createParser(input)) {
            var log = EventLog.read(parser);
            assertNotNull(log);
            assertNotNull(log.lastEventEntry().digestToWitness());
            
            var writer = new StringWriter();
            
            try (var gen = Json.createGenerator(writer)) {
                log.write(gen);
                gen.flush();
                
                
            }
            IO.println(writer.toString());
            
            
        }

    }

}
