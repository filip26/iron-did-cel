import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.apicatalog.jcs.Jcs;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.multicodec.codec.MultihashCodec;
import com.apicatalog.tree.io.TreeIOException;
import com.apicatalog.tree.io.jakarta.JakartaGenerator;
import com.apicatalog.tree.io.java.JavaAdapter;
import com.google.cloud.storage.Blob;

import jakarta.json.stream.JsonGeneratorFactory;
import jakarta.json.stream.JsonParser;
import jakarta.json.stream.JsonParserFactory;

class EventLog {

    @FunctionalInterface
    interface Save {
        void apply(String id, long generation, byte[] log);
    }

    private final long generation;
    private final Map<String, Object> root;

    private final Save persist;

    public EventLog(long generation, Map<String, Object> root, Save save) {
        this.generation = generation;
        this.root = root;
        this.persist = save;
    }

    public static final EventLog parse(Blob blob, JsonParserFactory factory) {
        try (var parser = factory.createParser(new ByteArrayInputStream(blob.getContent()))) {
            if (!parser.hasNext()) {
                throw new IllegalArgumentException();
            }
            return new EventLog(
                    blob.getGeneration(),
                    parse(parser), null);
        }
    }

    private static Map<String, Object> parse(JsonParser parser) {

        if (!parser.hasNext() || parser.next() != JsonParser.Event.START_OBJECT) {
            throw new IllegalArgumentException("A document root must be a JSON object");
        }

        var map = new LinkedHashMap<String, Object>();
        while (parser.hasNext()) {
            var next = parser.next();
            if (next == JsonParser.Event.END_OBJECT) {
                break;
            }
            // In OBJECT context, next is always KEY_NAME
            String key = parser.getString();
            map.put(key, processEvent(parser, parser.next()));
        }
        return map;
    }

    private static Object processEvent(JsonParser parser, JsonParser.Event event) {
        return switch (event) {
        case START_OBJECT -> {
            var map = new LinkedHashMap<String, Object>();
            while (parser.hasNext()) {
                var next = parser.next();
                if (next == JsonParser.Event.END_OBJECT) {
                    break;
                }
                // In OBJECT context, next is always KEY_NAME
                String key = parser.getString();
                map.put(key, processEvent(parser, parser.next()));
            }
            yield map;
        }
        case START_ARRAY -> {
            var list = new ArrayList<>();
            while (parser.hasNext()) {
                var next = parser.next();
                if (next == JsonParser.Event.END_ARRAY) {
                    break;
                }
                list.add(processEvent(parser, next));
            }
            yield list;
        }
        case VALUE_STRING -> parser.getString();
        case VALUE_NUMBER -> parser.getBigDecimal();
        case VALUE_TRUE -> Boolean.TRUE;
        case VALUE_FALSE -> Boolean.FALSE;
        case VALUE_NULL -> null;
        default -> null;
        };
    }

    public String lastEventHash() {

        var log = ((List) root.get("log"));

        var last = (Map<String, Object>) log.getLast();

        return methodSpecificId(last);
    }

    public void appendEvent(Map<String, Object> event) {
        var log = ((List) root.get("log"));
        log.add(Map.of("event", event));
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

    public long generation() {
        return generation;
    }

    public byte[] asByteArray(JsonGeneratorFactory factory) {

        var os = new ByteArrayOutputStream();

        try (final var gen = factory.createGenerator(os)) {
            final var writer = new JakartaGenerator(gen);
            writer.node(root, JavaAdapter.instance());

        } catch (TreeIOException e) {
            throw new IllegalStateException(e);
        }

        return os.toByteArray();
    }

}
