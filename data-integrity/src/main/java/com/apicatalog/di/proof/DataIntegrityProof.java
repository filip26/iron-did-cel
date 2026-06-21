package com.apicatalog.di.proof;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.Map;
import java.util.function.Function;

import com.apicatalog.di.suite.CryptoSuite;
import com.apicatalog.tree.io.Tree.NodeContext;
import com.apicatalog.tree.io.java.JavaTreeGenerator;
import com.apicatalog.trust.Proof;
import com.apicatalog.trust.Signature;
import com.apicatalog.tree.io.TreeGenerator;
import com.apicatalog.tree.io.TreeIOException;

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
            return canonize(ProofTemplates.getInstance(c14n));
        }

        public byte[] canonize(ProofTemplates.ProofCanonizer canonizer) {
            if (canonizer == null) {
                throw new IllegalArgumentException();
            }

            proof.canonicalPayload = canonizer.canonize(proof);
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
}
