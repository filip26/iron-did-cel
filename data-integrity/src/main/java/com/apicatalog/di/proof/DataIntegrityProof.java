package com.apicatalog.di.proof;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.function.Function;

import com.apicatalog.di.crypto.CryptoSuite;
import com.apicatalog.di.proof.c14.ProofTemplates;
import com.apicatalog.di.signature.Signature;
import com.apicatalog.tree.io.TreeGenerator;
import com.apicatalog.tree.io.TreeIOException;
import com.apicatalog.tree.io.Tree.NodeContext;

public final class DataIntegrityProof implements Proof {

    public static String SIMPLE_TYPE = "DataIntegrityProof";

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

    @Override
    public void write(TreeGenerator generator) throws TreeIOException {
        generator.beginMap(NodeContext.ROOT);
        writeEntry("id", id, generator);
        writeEntry("type", type(), generator);
        writeEntry("cryptosuite", cryptosuite, CryptoSuite::id, generator);
        writeEntry("created", created, Instant::toString, generator);
        writeEntry("expires", expires, Instant::toString, generator);
        if (domain != null && !domain.isEmpty()) {
            if (domain().size() == 1) {
                writeEntry("domain", domain.iterator().next(), generator);
            } else {
                generator.stringValue(NodeContext.ENTRY_KEY, "domain");
                generator.beginSequence(NodeContext.ENTRY_VALUE);
                for (var element : domain) {
                    generator.stringValue(NodeContext.ELEMENT, element);
                }
                generator.endSequence(NodeContext.ENTRY_VALUE);
            }
        }
        writeEntry("challenge", challenge, generator);
        writeEntry("nonce", nonce, generator);
        writeEntry("verificationMethod", verificationMethod, generator);
        writeEntry("proofPurpose", purpose, generator);
        if (cryptosuite != null) {
            writeEntry("proofValue", signature, cryptosuite::encode, generator);
        } else {
            writeEntry("proofValue", signature, Signature::toString, generator);
        }
        writeEntry("previousProof", previousProof, generator);
        generator.endMap(NodeContext.ROOT);
    }

    // TODO remove when TreeIO M2 released
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

    public Collection<String> domain() {
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
