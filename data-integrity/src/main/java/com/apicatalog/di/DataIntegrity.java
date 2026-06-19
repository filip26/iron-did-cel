package com.apicatalog.di;

import java.security.SignatureException;
import java.time.Instant;

import com.apicatalog.crypto.AsymmetricSigner;
import com.apicatalog.di.c14n.ProofTemplates;

public class DataIntegrity {

    
    public static ProofDraft newDraft(CryptoSuite suite) {
        return new Draft();
    }
    
    private static class Draft implements ProofDraft {

        ProofTemplates.C14nAlgorithm c14n;
        CryptoSuite crypto;
        
        @Override
        public ProofDraft created(Instant created) {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public DataIntegrityProof sign(AsymmetricSigner signer, byte[] canonicalData) throws SignatureException {
            
            var canonicalProof = c14n.canonize(null, null, null, null);
                    
            var digest = crypto.digest(canonicalProof, canonicalData);
            
            var signature = signer.sign(digest);
            
            var proof = new DataIntegrityProofImpl();
            proof.payload = canonicalProof;
            
            return proof;
        }

        @Override
        public DataIntegrityProof unsigned() {
            // TODO Auto-generated method stub
            return null;
        }
        
    }    
}
