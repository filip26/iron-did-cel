package com.apicatalog.di.proof;

import java.time.Instant;
import java.util.Collection;

import com.apicatalog.di.c14n.ProofTemplates;
import com.apicatalog.di.crypto.CryptoSuite;
import com.apicatalog.di.signature.Signature;

public final class DataIntegrityProof implements Proof {

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

    public static Draft newBuilder(CryptoSuite cryptosuite) {
        return new Draft(new DataIntegrityProof(cryptosuite));
    }
    
    public static class Draft {

        final DataIntegrityProof proof;

        Draft(DataIntegrityProof proof) {
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
            proof.created = created;
            return this;
        }

        public Draft expires(Instant expires) {
            proof.expires = expires;
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
