package com.apicatalog.di.proof;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Stream;

import com.apicatalog.di.suite.CryptoSuite;
import com.apicatalog.trust.Proof;
import com.apicatalog.trust.Signature;
import com.apicatalog.trust.document.CanonicalPayload;

public final class DataIntegrityProof implements Proof {

    public static String TYPE = "DataIntegrityProof";

    private String id;
    private CryptoSuite cryptosuite;
    private Instant created;
    private Instant expires;
    private Collection<String> domain;
    private String challenge;
    private String nonce;
    private String purpose;
    private String verificationMethod;
    private Signature signature;
    private String previousProof;

    private byte[] canonicalPayload;
    private String c14n;

    private DataIntegrityProof(CryptoSuite cryptosuite) {
        this.cryptosuite = cryptosuite;
    }

    public static Proof createProof(Map<String, String> map, Function<String, CanonicalPayload> canonicalDocument) {

        return null;
    }
//
//    public static void write(DataIntegrityProof proof, TreeEmitter emitter) throws IOException {
//        emitter.beginMap(NodeContext.ROOT);
//        emitter.entry("id", proof.id());
//        emitter.entry("type", proof.type());
//        emitter.entry("cryptosuite", proof.cryptosuite(), CryptoSuite::id);
//        emitter.entry("created", proof.created(), Instant::toString);
//        emitter.entry("expires", proof.expires(), Instant::toString);
//        if (proof.domains() != null && !proof.domains().isEmpty()) {
//            if (proof.domains().size() == 1) {
//                emitter.entry("domain", proof.domains().iterator().next());
//            } else {
//                emitter.stringValue(NodeContext.ENTRY_KEY, "domain");
//                emitter.beginSequence(NodeContext.ENTRY_VALUE);
//                int it = 0;
//                for (var domain : proof.domains()) {
//                    emitter.stringValue(it++ == proof.domains().size() ? NodeContext.LAST_ELEMENT : NodeContext.ELEMENT, domain);
//                }
//                emitter.endSequence(NodeContext.ENTRY_VALUE);
//            }
//        }
//        emitter.entry("challenge", proof.challenge());
//        emitter.entry("nonce", proof.nonce());
//        emitter.entry("verificationMethod", proof.verificationMethod());
//        emitter.entry("proofPurpose", proof.purpose());
//        if (proof.cryptosuite() != null) {
//            emitter.entry("proofValue", proof.signature(), proof.cryptosuite()::encode);
//        } else {
//            emitter.entry("proofValue", proof.signature(), Signature::toString);
//        }
//        emitter.entry("previousProof", proof.previousProof());
//        emitter.endMap(NodeContext.ROOT);
//    }

    public static Map<String, Object> toMap(DataIntegrityProof proof) {
        var map = new LinkedHashMap<String, Object>(12);

        if (proof.id != null) {
            map.put("id", proof.id());
        }
        if (proof.type() != null) {
            map.put("type", proof.type());
        }
        if (proof.cryptosuite() != null) {
            map.put("cryptosuite", proof.cryptosuite().id());
        }
        if (proof.created() != null) {
            map.put("created", proof.created().toString());
        }
        if (proof.expires() != null) {
            map.put("expires", proof.expires().toString());
        }
        if (proof.domains() != null && !proof.domains().isEmpty()) {
            if (proof.domains().size() == 1) {
                map.put("domain", proof.domains().iterator().next());
            } else {
                map.put("domain", proof.domains());
            }
        }
        if (proof.challenge() != null) {
            map.put("challenge", proof.challenge());
        }
        if (proof.nonce() != null) {
            map.put("nonce", proof.nonce());
        }
        if (proof.verificationMethod() != null) {
            map.put("verificationMethod", proof.verificationMethod());
        }
        if (proof.purpose() != null) {
            map.put("proofPurpose", proof.purpose());
        }
        if (proof.signature() != null) {
            if (proof.cryptosuite() != null) {
                map.put("proofValue", proof.cryptosuite().encode(proof.signature()));
            } else {
                map.put("proofValue", proof.signature().toString());
            }
        }
        map.put("previousProof", proof.previousProof());

        return map;
    }

    public static Draft createDraft(CryptoSuite cryptosuite) {
        return new Draft(new DataIntegrityProof(cryptosuite));
    }

    public static final class Draft {

        private final DataIntegrityProof proof;

        private Draft(DataIntegrityProof proof) {
            this.proof = proof;
        }

        public byte[] canonize(String c14n) {
            return canonize(DataIntegrityProof.getTemplate(c14n));
        }

        public byte[] canonize(Function<DataIntegrityProof, byte[]> canonizer) {
            if (canonizer == null) {
                throw new IllegalArgumentException();
            }

            proof.canonicalPayload = canonizer.apply(proof);
            return proof.canonicalPayload;
        }

        public DataIntegrityProof get() {
            return proof;
        }

        public Draft created(Instant created) {
            proof.created = created != null
                    ? created.truncatedTo(ChronoUnit.SECONDS)
                    : null;
            return this;
        }

        public Draft expires(Instant expires) {
            proof.expires = expires != null
                    ? expires.truncatedTo(ChronoUnit.SECONDS)
                    : null;
            return this;
        }

        public Draft purpose(String purpose) {
            proof.purpose = purpose;
            return this;
        }

        public Draft verificationMethod(String verificationMethod) {
            proof.verificationMethod = verificationMethod;
            return this;
        }

        public Draft id(String id) {
            proof.verificationMethod = id;
            return this;
        }

        public Draft challenge(String challenge) {
            proof.challenge = challenge;
            return this;
        }

        public Draft nonce(String nonce) {
            proof.nonce = nonce;
            return this;
        }

        public Draft previousProof(String previousProof) {
            proof.previousProof = previousProof;
            return this;
        }

        public Draft signature(Signature signature) {
            proof.signature = signature;
            return this;

        }
    }

    public String id() {
        return id;
    }

    public CryptoSuite cryptosuite() {
        return cryptosuite;
    }

    public Instant created() {
        return created;
    }

    public Instant expires() {
        return expires;
    }

    public Collection<String> domains() {
        return domain;
    }

    public String challenge() {
        return challenge;
    }

    public String nonce() {
        return nonce;
    }

    public String previousProof() {
        return previousProof;
    }

    @Override
    public byte[] canonicalPayload() {
        return canonicalPayload;
    }

    @Override
    public String c14n() {
        return c14n;
    }

    @Override
    public String type() {
        return "DataIntegrityProof";
    }

    @Override
    public Signature signature() {
        return signature;
    }

    @Override
    public String verificationMethod() {
        return verificationMethod;
    }

    @Override
    public String purpose() {
        return purpose;
    }

    private static final byte[][] RDFC_TEMPLATE = Stream.of(
            "_:c14n0",
            " <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .",

            " <http://purl.org/dc/terms/created> \"",
            "\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .",

            " <https://vc.ex/1> <https://w3id.org/security#challenge> \"",
            "\" .",

            " <https://w3id.org/security#cryptosuite> \"",
            "\"^^<https://w3id.org/security#cryptosuiteString> .",

            " <https://w3id.org/security#domain> \"",
            "\" .",

            " <https://w3id.org/security#expiration> \"",
            "\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .",

            " <https://w3id.org/security#nonce> \"",
            "\" .",

            "<https://vc.ex/1> <https://w3id.org/security#previousProof> <",
            "> .",

            " <https://w3id.org/security#proofPurpose> <https://w3id.org/security#",
            "> .",

            " <https://w3id.org/security#verificationMethod> <",
            "> .")
            .map(i -> i.getBytes(StandardCharsets.UTF_8))
            .toArray(byte[][]::new);

    private static final byte[][] JCS_TEMPLATE = Stream.of(
            "\"type\":\"DataIntegrityProof\"",

            "\"challenge\":\"",
            "\"created\":\"",
            "\"cryptosuite\":\"",
            "\"domain\":",
            "\"expires\":\"",
            "\"id\":\"",
            "\"nonce\":\"",
            "\"previousProof\":\"",
            "\"purpose\":\"",
            "\"verificationMethod\":\"")
            .map(i -> i.getBytes(StandardCharsets.UTF_8))
            .toArray(byte[][]::new);

    private static Function<DataIntegrityProof, byte[]> getTemplate(String c14n) {
        return switch (c14n) {
        case "JCS" -> DataIntegrityProof::jcs;
        case "RDFC" -> DataIntegrityProof::rdfc;
        default -> throw new IllegalArgumentException();
        };
    }

    /**
     * Builds the canonical JSON proof (JCS) for hashing/signing.
     *
     * @param proof
     * @return UTF-8 encoded JSON proof bytes
     */
    private static byte[] jcs(DataIntegrityProof proof) {
        try {
            var os = new ByteArrayOutputStream();
            os.write('{');

            var next = writeJcsEntry(1, proof.challenge(), os, false);
            next = writeJcsEntry(2, proof.created(), Instant::toString, os, next);
            next = writeJcsEntry(3, proof.cryptosuite(), CryptoSuite::id, os, next);
            if (proof.domains() != null && !proof.domains().isEmpty()) {
                if (next) {
                    os.write(',');
                }
                os.write(JCS_TEMPLATE[4]);
                if (proof.domains().size() == 1) {
                    os.write('"');
                    os.write(proof.domains().iterator().next().getBytes(StandardCharsets.UTF_8));
                    os.write('"');
                } else {
                    os.write('[');
                    boolean first = true;
                    for (var domain : proof.domains()) {
                        if (!first) {
                            os.write(',');
                        } else {
                            first = false;
                        }
                        os.write('"');
                        os.write(domain.getBytes(StandardCharsets.UTF_8));
                        os.write('"');
                    }
                    os.write(']');
                }
                next = true;
            }
            next = writeJcsEntry(5, proof.expires(), Instant::toString, os, next);
            next = writeJcsEntry(6, proof.id(), os, next);
            next = writeJcsEntry(7, proof.nonce(), os, next);
            next = writeJcsEntry(8, proof.previousProof(), os, next);
            next = writeJcsEntry(9, proof.purpose(), os, next);

            if (next) {
                os.write(',');
            }
            os.write(JCS_TEMPLATE[0]); // type
            writeJcsEntry(10, proof.verificationMethod(), os, true);

            os.write('}');

            return os.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Builds the deterministic N-Quads representation of a DataIntegrityProof for
     * RDF Dataset Canonicalization (RDFC).
     *
     * <p>
     * The returned value is UTF-8 encoded and suitable for hashing or signing. The
     * output strictly follows N-Quads syntax and is deterministic for the supplied
     * values.
     * </p>
     *
     * @param proof
     * @return UTF-8 encoded canonical N-Quads proof representation
     */
    private static byte[] rdfc(DataIntegrityProof proof) {

        byte[] id = proof.id() != null
                ? ("<" + proof.id() + ">").getBytes(StandardCharsets.UTF_8)
                : RDFC_TEMPLATE[0];

        try {
            var os = new ByteArrayOutputStream();

            writeRdfcEntry(id, 2, proof.created(), Instant::toString, os);

            os.write(id);
            os.write(RDFC_TEMPLATE[1]);
            os.write('\n');

            writeRdfcEntry(id, 4, proof.challenge(), os);
            writeRdfcEntry(id, 6, proof.cryptosuite(), CryptoSuite::id, os);

            if (proof.domains() != null && !proof.domains().isEmpty()) {
                for (var domain : proof.domains()) {
                    writeRdfcEntry(id, 8, domain, os);
                }
            }
            writeRdfcEntry(id, 10, proof.expires(), Instant::toString, os);
            writeRdfcEntry(id, 12, proof.nonce(), os);
            writeRdfcEntry(id, 14, proof.previousProof(), os);
            writeRdfcEntry(id, 16, proof.purpose(), os);
            writeRdfcEntry(id, 18, proof.verificationMethod(), os);

            return os.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static <T> void writeRdfcEntry(byte[] id, int index, String value, OutputStream os) throws IOException {
        if (value != null) {
            os.write(id);
            os.write(RDFC_TEMPLATE[index]);
            os.write(value.getBytes(StandardCharsets.UTF_8));
            os.write(RDFC_TEMPLATE[index + 1]);
            os.write('\n');
        }
    }

    private static <T> void writeRdfcEntry(byte[] id, int index, T value, Function<T, String> map, OutputStream os)
            throws IOException {
        if (value != null) {
            writeRdfcEntry(id, index, map.apply(value), os);
        }
    }

    private static <T> boolean writeJcsEntry(int index, String value, OutputStream os, boolean next)
            throws IOException {
        if (value != null) {
            if (next) {
                os.write(',');
            }
            os.write(JCS_TEMPLATE[index]);
            os.write(escape(value));
            os.write('\"');
            return true;
        }
        return next;
    }

    private static <T> boolean writeJcsEntry(int index, T value, Function<T, String> map, OutputStream os, boolean next)
            throws IOException {
        if (value != null) {
            if (next) {
                os.write(',');
            }
            os.write(JCS_TEMPLATE[index]);
            os.write(map.apply(value).getBytes(StandardCharsets.UTF_8));
            os.write('\"');
            return true;
        }
        return next;
    }

    /**
     * Escapes a string according to JCS (RFC 8785, Section 2.5) rules and encodes
     * the result directly to a UTF-8 byte array.
     *
     * @param value the string to escape
     * @return the escaped UTF-8 byte array
     * @throws IllegalArgumentException if invalid Unicode data (lone surrogates) is
     *                                  detected
     */
    static byte[] escape(String value) {
        final int length = value.length();
        final ByteArrayOutputStream out = new ByteArrayOutputStream(Math.max(length, 16));
        final HexFormat hexFormat = HexFormat.of();

        for (int i = 0; i < length;) {
            int ch = value.codePointAt(i);
            switch (ch) {
            case '\t' -> {
                out.write('\\');
                out.write('t');
            }
            case '\b' -> {
                out.write('\\');
                out.write('b');
            }
            case '\n' -> {
                out.write('\\');
                out.write('n');
            }
            case '\r' -> {
                out.write('\\');
                out.write('r');
            }
            case '\f' -> {
                out.write('\\');
                out.write('f');
            }
            case '\"' -> {
                out.write('\\');
                out.write('"');
            }
            case '\\' -> {
                out.write('\\');
                out.write('\\');
            }
            default -> {
                if (ch <= 0x1F) {
                    out.write('\\');
                    out.write('u');
                    out.write('0');
                    out.write('0');
                    out.write(hexFormat.toHighHexDigit((byte) ch));
                    out.write(hexFormat.toLowHexDigit((byte) ch));

                } else if (ch >= 0xD800 && ch <= 0xDFFF) {
                    throw new IllegalArgumentException(
                            "RFC 8785 Compliance Error: Invalid Unicode data (lone surrogate) detected at index " + i);
                } else if (ch <= 0x7F) {
                    out.write(ch);

                } else if (ch <= 0x7FF) {
                    out.write(0xC0 | (ch >> 6));
                    out.write(0x80 | (ch & 0x3F));

                } else if (ch <= 0xFFFF) {
                    out.write(0xE0 | (ch >> 12));
                    out.write(0x80 | ((ch >> 6) & 0x3F));
                    out.write(0x80 | (ch & 0x3F));

                } else {
                    out.write(0xF0 | (ch >> 18));
                    out.write(0x80 | ((ch >> 12) & 0x3F));
                    out.write(0x80 | ((ch >> 6) & 0x3F));
                    out.write(0x80 | (ch & 0x3F));
                }
            }
            }
            i += Character.charCount(ch);
        }
        return out.toByteArray();
    }
}
