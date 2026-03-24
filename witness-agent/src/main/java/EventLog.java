import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

import jakarta.json.stream.JsonGenerator;
import jakarta.json.stream.JsonGeneratorFactory;
import jakarta.json.stream.JsonParser;

class EventLog {

    private final List<EventEntry> events;

    public EventLog(List<EventEntry> events) {
        this.events = events;
    }

    public static final EventLog parse(JsonParser parser) {

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
                    if (parser.next() == JsonParser.Event.END_ARRAY) {
                        break;
                    }
                    events.add(EventEntry.read(parser));
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
        return events.getLast();
    }

    public int size() {
        return events.size();
    }

    public byte[] toByteArray(JsonGeneratorFactory factory) {

        var bos = new ByteArrayOutputStream();

        try (var gen = factory.createGenerator(bos)) {
            write(gen);
        }

        return bos.toByteArray();
    }

    public void write(JsonGenerator gen) {
        gen.writeStartObject();
        gen.write("log");
        for (var event : events) {
            event.write(gen);
        }
        gen.writeEnd();
    }
}
