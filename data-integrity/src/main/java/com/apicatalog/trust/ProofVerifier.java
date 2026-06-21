package com.apicatalog.trust;

import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Map;

public class ProofVerifier {

    MethodResolver methodResolvers;
    Map<String, AsymmetricVerifier> verifiers;

    protected ProofVerifier() {
        
    }
    
    public static Builder createBuilder() {

        return new Builder();
    }

    public boolean verify(Proof proof) throws InvalidKeyException, SignatureException {

        if (proof.signature() == null) {
            return false;
        }

        var algorithm = proof.signature().algorithm();
        
        var publicKey = methodResolvers.resolve(
                proof.verificationMethod(),
                proof.purpose(),
                algorithm);

        return verify(proof, publicKey);
    }

    public boolean verify(Proof proof, byte[] publicKey) throws InvalidKeyException, SignatureException {

        if (proof.signature() == null) {
            return false;
        }

        var verifier = verifiers.get(proof.signature().algorithm());

        if (proof.signature() instanceof AtomicSignature atomic) {
            return atomic.verify(verifier, publicKey);
        }
        
        throw new SignatureException();
    }
    
    public static class Builder {
        
        
        public ProofVerifier build() {
            return null;
        }
    }
}
