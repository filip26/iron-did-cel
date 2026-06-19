package com.apicatalog.di;

import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.time.Instant;
import java.util.Map;

import com.apicatalog.crypto.AsymmetricSigner;
import com.apicatalog.di.c14n.ProofTemplates;

public class DataIntegrity {

    public static ProofVerifierBuilder newVerifier() {
        
        return null;
    }
    
    public static ProofBuilder newProof(CryptoSuite cryptosuite) {

        var c14n = ProofTemplates.get(cryptosuite.c14n());

        if (c14n == null) {
            throw new IllegalArgumentException();
        }

        return new ProofBuilder(cryptosuite, c14n);
    }
    
    public static class Verifier {
 
        public boolean verify(DataIntegrityProof proof, byte[] publicKey) throws InvalidKeyException, SignatureException {
            
            
            proof.signature().verify(null, publicKey);
            
            //TODO
            return false;
        }
    }
    
    public static class ProofVerifierBuilder {
        
    }

    public static class ProofBuilder {

        final DataIntegrityProofImpl proof;
        final ProofTemplates.C14nAlgorithm c14n;

        private ProofBuilder(CryptoSuite cryptosuite, ProofTemplates.C14nAlgorithm c14n) {
            this.proof = new DataIntegrityProofImpl();
            this.proof.cryptosuite = cryptosuite;
            this.c14n = c14n;
        }

        public ProofBuilder created(Instant created) {
            proof.created = created;
            return this;
        }

        public ProofBuilder expires(Instant expires) {
            proof.expires = expires;
            return this;
        }

        public DataIntegrityProof sign(AsymmetricSigner signer, CanonicalDocument document) throws SignatureException {

            if (!proof.cryptosuite.c14n.equals(document.c14n())) {
                throw new IllegalArgumentException();
            }

            proof.payload = c14n.canonize(proof);
            proof.signature = new SignatureImpl();
            proof.signature.digest = proof.cryptosuite.digest(proof.payload, document.payload());
            proof.signature.signature = signer.sign(proof.signature.digest);
            proof.signature.document = document;
            proof.signature.proof = proof;
            return proof;
        }

        public DataIntegrityProof unsigned() {
            return proof;
        }

    }
}
