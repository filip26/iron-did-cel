package com.apicatalog.di;

import java.security.SignatureException;
import java.time.Instant;

import com.apicatalog.crypto.AsymmetricSigner;
import com.apicatalog.di.c14n.ProofTemplates;
import com.apicatalog.iron.CanonicalDocument;

public class DataIntegrity {


    public static Signer newSigner(CryptoSuite cryptosuite, AsymmetricSigner signer) {

        var c14n = ProofTemplates.get(cryptosuite.c14n());

        if (c14n == null) {
            throw new IllegalArgumentException();
        }

        return new Signer(cryptosuite, signer, c14n);
    }

    public static class Signer {

        final CryptoSuite cryptosuite;
        final AsymmetricSigner signer;
        final ProofTemplates.C14nAlgorithm c14n;
        
        Instant created;
        Instant expires;

        private Signer(CryptoSuite cryptosuite, AsymmetricSigner signer, ProofTemplates.C14nAlgorithm c14n) {
            this.cryptosuite = cryptosuite;
            this.signer = signer;
            this.c14n = c14n;
        }

        public Signer created(Instant created) {
            created = created;
            return this;
        }

        public Signer expires(Instant expires) {
            expires = expires;
            return this;
        }

        public DataIntegrityProof sign(CanonicalDocument document) throws SignatureException {
            return sign(signer, document);
        }

        public DataIntegrityProof sign(AsymmetricSigner customSigner, CanonicalDocument document) throws SignatureException {

            if (!cryptosuite.c14n.equals(document.c14n())) {
                throw new IllegalArgumentException();
            }

            var proof = (DataIntegrityProofImpl) unsigned();
            proof.signature = new DataIntegritySignature();
            proof.signature.digest = proof.cryptosuite.digest(proof.payload, document.canonicalPayload());
            proof.signature.signature = customSigner.sign(proof.signature.digest);
            proof.signature.document = document;
            proof.signature.proof = proof;
            return proof;
        }

        public DataIntegrityProof unsigned() {
            var proof = new DataIntegrityProofImpl();
            proof.payload = c14n.canonize(proof);
            return proof;
        }

    }
}
