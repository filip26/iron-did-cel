package com.apicatalog.di;

import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.time.Instant;
import java.util.Map;

import com.apicatalog.crypto.AsymmetricSigner;
import com.apicatalog.di.c14n.ProofTemplates;
import com.apicatalog.iron.CanonicalDocument;

public class DataIntegrity {

    public static ProofVerifierBuilder newVerifier() {
        
        return null;
    }
    
    public static Signer newSigner(CryptoSuite cryptosuite) {

        var c14n = ProofTemplates.get(cryptosuite.c14n());

        if (c14n == null) {
            throw new IllegalArgumentException();
        }

        return new Signer(cryptosuite, c14n);
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

    public static class Signer {

        final DataIntegrityProofImpl proof;
        final ProofTemplates.C14nAlgorithm c14n;

        private Signer(CryptoSuite cryptosuite, ProofTemplates.C14nAlgorithm c14n) {
            this.proof = new DataIntegrityProofImpl();
            this.proof.cryptosuite = cryptosuite;
            this.c14n = c14n;
        }

        public Signer created(Instant created) {
            proof.created = created;
            return this;
        }

        public Signer expires(Instant expires) {
            proof.expires = expires;
            return this;
        }

        public DataIntegrityProof sign(AsymmetricSigner signer, CanonicalDocument document) throws SignatureException {

            if (!proof.cryptosuite.c14n.equals(document.c14n())) {
                throw new IllegalArgumentException();
            }

            proof.payload = c14n.canonize(proof);
            proof.signature = new DataIntegritySignature();
            proof.signature.digest = proof.cryptosuite.digest(proof.payload, document.canonicalPayload());
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
