package com.apicatalog.di.proof;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import com.apicatalog.crypto.AsymmetricSigner;
import com.apicatalog.di.c14n.CanonicalPayload;
import com.apicatalog.di.signature.AtomicSignature;
import com.apicatalog.di.signature.Signature;

public final class Ed25519Signature2020 implements Proof {

    private Instant created;
    private String purpose;
    private String verificationMethod;
    private Signature signature;

    private byte[] canonicalPayload;
    private String c14n;

    private Ed25519Signature2020() {
    }

    public Ed25519Signature2020 generateProof(
            AsymmetricSigner signer,
            Ed25519Signature2020.Draft proofDraft,
            CanonicalPayload canonicalDocument) throws SignatureException {

        try {
            proofDraft.canonize(c14n);

            var signature = AtomicSignature.generateSignature(
                    signer,
                    "Ed25519",
                    MessageDigest.getInstance("SHA-256"),
                    proofDraft.get(),
                    canonicalDocument);

            proofDraft.signature(signature);
            
            return proofDraft.get();

        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static Draft newDraft() {
        return new Draft(new Ed25519Signature2020());
    }

    public static final class Draft {

        private final Ed25519Signature2020 proof;

        private Draft(Ed25519Signature2020 proof) {
            this.proof = proof;
        }

        public byte[] canonize(String c14n) {
            proof.canonicalPayload = Ed25519Signature2020.canonize(proof);
            return proof.canonicalPayload;
        }

        public Ed25519Signature2020 get() {
            return proof;
        }

        public Draft created(Instant created) {
            proof.created = created;
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
        return "Ed25519Signature2020";
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

    final static byte[][] RDFC_TEMPLATE = new byte[][] {
            "_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Ed25519Signature2020> ."
                    .getBytes(StandardCharsets.UTF_8),

            "_:c14n0 <http://purl.org/dc/terms/created> \"".getBytes(StandardCharsets.UTF_8),
            "\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .".getBytes(StandardCharsets.UTF_8),

            "_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#"
                    .getBytes(StandardCharsets.UTF_8),
            "> .".getBytes(StandardCharsets.UTF_8),

            "_:c14n0 <https://w3id.org/security#verificationMethod> <".getBytes(StandardCharsets.UTF_8),
            "> .".getBytes(StandardCharsets.UTF_8)
    };

    private static byte[] canonize(Ed25519Signature2020 proof) {
        try {
            var os = new ByteArrayOutputStream();
            if (proof.created != null) {
                os.write(RDFC_TEMPLATE[1]);
                os.write(proof.created.truncatedTo(ChronoUnit.SECONDS).toString().getBytes(StandardCharsets.UTF_8));
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
}
