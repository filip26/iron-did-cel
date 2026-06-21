package com.apicatalog.di.proof;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Stream;

import com.apicatalog.di.suite.CryptoSuite;
import com.apicatalog.tree.io.Tree.NodeContext;
import com.apicatalog.tree.io.TreeGenerator;
import com.apicatalog.tree.io.TreeIOException;
import com.apicatalog.tree.io.java.JavaTreeGenerator;
import com.apicatalog.trust.Proof;
import com.apicatalog.trust.Signature;

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

    public static void write(DataIntegrityProof proof, TreeGenerator generator) throws TreeIOException {
        generator.beginMap(NodeContext.ROOT);
        writeEntry("id", proof.id(), generator);
        writeEntry("type", proof.type(), generator);
        writeEntry("cryptosuite", proof.cryptosuite(), CryptoSuite::id, generator);
        writeEntry("created", proof.created(), Instant::toString, generator);
        writeEntry("expires", proof.expires(), Instant::toString, generator);
        if (proof.domains() != null && !proof.domains().isEmpty()) {
            if (proof.domains().size() == 1) {
                writeEntry("domain", proof.domains().iterator().next(), generator);
            } else {
                generator.stringValue(NodeContext.ENTRY_KEY, "domain");
                generator.beginSequence(NodeContext.ENTRY_VALUE);
                for (var domain : proof.domains()) {
                    generator.stringValue(NodeContext.ELEMENT, domain);
                }
                generator.endSequence(NodeContext.ENTRY_VALUE);
            }
        }
        writeEntry("challenge", proof.challenge(), generator);
        writeEntry("nonce", proof.nonce(), generator);
        writeEntry("verificationMethod", proof.verificationMethod(), generator);
        writeEntry("proofPurpose", proof.purpose(), generator);
        if (proof.cryptosuite() != null) {
            writeEntry("proofValue", proof.signature(), proof.cryptosuite()::encode, generator);
        } else {
            writeEntry("proofValue", proof.signature(), Signature::toString, generator);
        }
        writeEntry("previousProof", proof.previousProof(), generator);
        generator.endMap(NodeContext.ROOT);
    }

    public static Map<String, String> toMap(DataIntegrityProof proof) throws TreeIOException {
        var generator = new JavaTreeGenerator();
        write(proof, generator);
        return generator.get();
    }
    
    //TODO remove when TreeIO M2 released
    static void writeEntry(String key, String value, TreeGenerator generator) throws TreeIOException {
        if (value != null) {
            generator.stringValue(NodeContext.ENTRY_KEY, key);
            generator.stringValue(NodeContext.ENTRY_VALUE, value);
        }
    }

    static <T> void writeEntry(String key, T object, Function<T, String> map, TreeGenerator generator)
            throws TreeIOException {
        if (object != null) {
            generator.stringValue(NodeContext.ENTRY_KEY, key);
            generator.stringValue(NodeContext.ENTRY_VALUE, map.apply(object));
        }
    }
    
    public static Draft newDraft(CryptoSuite cryptosuite) {
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
    private static final byte[] jcs(DataIntegrityProof proof) {
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
    private static final byte[] rdfc(DataIntegrityProof proof) {

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
            os.write(value.getBytes(StandardCharsets.UTF_8));
            os.write('\"');
            return true;
        }
        return next;
    }

    private static <T> boolean writeJcsEntry(int index, T value, Function<T, String> map, OutputStream os, boolean next)
            throws IOException {
        if (value != null) {
            return writeJcsEntry(index, map.apply(value), os, next);
        }
        return next;
    }
}
