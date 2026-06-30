package com.apicatalog.di.proof;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.stream.Stream;

import com.apicatalog.di.signature.ProofValue;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.security.AsymmetricSigner;
import com.apicatalog.tree.io.Tree;
import com.apicatalog.tree.io.TreeEmitter;
import com.apicatalog.trust.Proof;
import com.apicatalog.trust.Signature;
import com.apicatalog.trust.document.DigestiblePayload;
import com.apicatalog.trust.proof.ProofGraphReader;

public final class Ed25519Signature2020 implements Proof {

    public static String TYPE_NAME = "Ed25519Signature2020";
    public static String KEY_ALGORITHM = "Ed25519";
    public static String HASH_ALGORITHM = "SHA-256";
    public static String C14N = "RDFC";

    private Instant created;
    private String purpose;
    private String verificationMethod;
    private Signature signature;

    private byte[] canonicalPayload;
    private String c14n;

    private Ed25519Signature2020() {
    }

    public static void write(Ed25519Signature2020 proof, TreeEmitter emitter) {
        var writer = Tree.createPropertyTree(emitter)
                .beginMap()
                .entry("type", proof.type())
                .entry("created", proof.created, Instant::toString)
                .entry("verificationMethod", proof.verificationMethod)
                .entry("proofPurpose", proof.purpose);
        if (proof.signature != null) {
            writer.entry(
                    "proofValue",
                    proof.signature.toByteArray(),
                    Multibase.BASE_58_BTC::encode);
        }
        writer.endMap();
    }

    public static Ed25519Signature2020 generateProof(
            AsymmetricSigner signer,
            Ed25519Signature2020.Draft proofDraft,
            DigestiblePayload canonicalDocument) throws SignatureException {

        try {
            proofDraft.canonize();

            var signature = ProofValue.generateSignature(
                    signer,
                    Ed25519Signature2020.KEY_ALGORITHM,
                    MessageDigest.getInstance(HASH_ALGORITHM),
                    proofDraft.get(),
                    canonicalDocument);

            proofDraft.signature(signature);

            return proofDraft.get();

        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static Draft createDraft() {
        return new Draft(new Ed25519Signature2020());
    }

    public static Draft createDraft(Map<String, String> map) {

        var proof = new Ed25519Signature2020();

        for (var entry : map.entrySet()) {
            switch (entry.getKey()) {
            case "created":
                proof.created = Instant.parse(entry.getValue());
                break;
            case "proofPurpose":
                proof.purpose = entry.getValue();
                break;
            case "verificationMethod":
                proof.verificationMethod = entry.getValue();
                break;
            }
        }

        return new Draft(proof);
    }

    public static final class Draft {

        private final Ed25519Signature2020 proof;

        private Draft(Ed25519Signature2020 proof) {
            this.proof = proof;
        }

        public byte[] canonize() {
            proof.canonicalPayload = Ed25519Signature2020.canonize(proof);
            return proof.canonicalPayload;
        }

        public Ed25519Signature2020 get() {
            return proof;
        }

        public Draft created(Instant created) {
            proof.created = created != null
                    ? created.truncatedTo(ChronoUnit.SECONDS)
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

        public Draft signature(Signature signature) {
            proof.signature = signature;
            return this;
        }
    }

    public Instant created() {
        return created;
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
        return TYPE_NAME;
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

    private final static byte[][] RDFC_TEMPLATE = Stream.of(
            "_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Ed25519Signature2020> .",

            "_:c14n0 <http://purl.org/dc/terms/created> \"",
            "\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .",

            "_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#",
            "> .",

            "_:c14n0 <https://w3id.org/security#verificationMethod> <",
            "> .")
            .map(i -> i.getBytes(StandardCharsets.UTF_8))
            .toArray(byte[][]::new);

    private static byte[] canonize(Ed25519Signature2020 proof) {
        try {
            var os = new ByteArrayOutputStream();
            if (proof.created != null) {
                os.write(RDFC_TEMPLATE[1]);
                os.write(proof.created.toString().getBytes(StandardCharsets.UTF_8));
                os.write(RDFC_TEMPLATE[2]);
                os.write('\n');
            }

            os.write(RDFC_TEMPLATE[0]);
            os.write('\n');

            if (proof.purpose != null) {
                os.write(RDFC_TEMPLATE[3]);
                os.write(proof.purpose.getBytes(StandardCharsets.UTF_8));
                os.write(RDFC_TEMPLATE[4]);
                os.write('\n');
            }

            if (proof.verificationMethod != null) {
                os.write(RDFC_TEMPLATE[5]);
                os.write(proof.verificationMethod.getBytes(StandardCharsets.UTF_8));
                os.write(RDFC_TEMPLATE[6]);
                os.write('\n');
            }

            return os.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public static ProofGraphReader createReader() {

        return null;
    }

    @Override
    public DigestiblePayload document() {
        // TODO Auto-generated method stub
        return null;
    }
}
