package com.apicatalog.di;

import java.security.SignatureException;
import java.time.Instant;
import java.util.Map;

import com.apicatalog.crypto.AsymmetricSigner;
import com.apicatalog.di.c14n.ProofTemplates;

public class DataIntegrity {

    public static ProofBuilder newProof(CryptoSuite cryptosuite) {
        return new ProofBuilder(cryptosuite);
    }

    public static class ProofBuilder {

        final DataIntegrityProofImpl proof;
        final ProofTemplates.C14nAlgorithm c14n;

        private ProofBuilder(CryptoSuite cryptosuite) {
            this.proof = new DataIntegrityProofImpl();
            this.proof.cryptosuite = cryptosuite;
            this.c14n = ProofTemplates.get(cryptosuite.c14n());
        }

        public ProofBuilder created(Instant created) {
            proof.created = created;
            return this;
        }

        public ProofBuilder expires(Instant expires) {
            proof.expires = expires;
            return this;
        }

        public ProofBuilder sign(AsymmetricSigner signer, Map<String, Object> document) throws SignatureException {
//
//            var canonicalData = null;
//            
//            return sign(signer, canonicalData);
            return null;
        }

        public DataIntegrityProof sign(AsymmetricSigner signer, byte[] canonicalData) throws SignatureException {
            proof.payload = c14n.canonize(proof);
            proof.signature = new SignatureImpl();
            proof.signature.digest = proof.cryptosuite.digest(proof.payload, canonicalData);
            proof.signature.signature = signer.sign(proof.signature.digest);
            return proof;
        }

        public DataIntegrityProof unsigned() {
            return proof;
        }

    }
}
