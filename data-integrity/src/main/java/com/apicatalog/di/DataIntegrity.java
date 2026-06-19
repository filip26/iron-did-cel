package com.apicatalog.di;

import java.security.SignatureException;
import java.time.Instant;
import java.util.Map;

import com.apicatalog.crypto.AsymmetricSigner;
import com.apicatalog.di.c14n.ProofTemplates;

public class DataIntegrity {

    public static ProofDraft newDraft(CryptoSuite cryptosuite) {
        return new Draft(cryptosuite);
    }

    private static class Draft implements DataIntegerityProofDraft {

        final DataIntegrityProofImpl proof;
        final ProofTemplates.C14nAlgorithm c14n;

        Draft(CryptoSuite cryptosuite) {
            this.proof = new DataIntegrityProofImpl();
            this.proof.cryptosuite = cryptosuite;
            this.c14n = ProofTemplates.get(cryptosuite.c14n());
        }

        @Override
        public DataIntegerityProofDraft created(Instant created) {
            proof.created = created;
            return this;
        }

        @Override
        public DataIntegerityProofDraft expires(Instant expires) {
            proof.expires = expires;
            return this;
        }

        @Override
        public DataIntegrityProof sign(AsymmetricSigner signer, Map<String, Object> document) throws SignatureException {
//
//            var canonicalData = null;
//            
//            return sign(signer, canonicalData);
            return null;
        }

        @Override
        public DataIntegrityProof sign(AsymmetricSigner signer, byte[] canonicalData) throws SignatureException {
            proof.payload = c14n.canonize(proof);
            proof.signature = new SignatureImpl();
            proof.signature.digest = proof.cryptosuite.digest(proof.payload, canonicalData);
            proof.signature.signature = signer.sign(proof.signature.digest);
            return proof;
        }

        @Override
        public DataIntegrityProof unsigned() {
            return proof;
        }

    }
}
