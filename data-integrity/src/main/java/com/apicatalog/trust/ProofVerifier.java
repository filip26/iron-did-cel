package com.apicatalog.trust;

import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.Map;

import com.apicatalog.security.AsymmetricVerifier;

public class ProofVerifier {

    final Map<String, MethodResolver> methodResolvers;
    final Map<String, AsymmetricVerifier> verifiers;

    protected ProofVerifier(Map<String, MethodResolver> methodResolvers, Map<String, AsymmetricVerifier> verifiers) {
        this.methodResolvers = methodResolvers;
        this.verifiers = verifiers;
    }
    
    public static Builder createBuilder() {

        return new Builder();
    }

    public boolean verify(Proof proof) throws InvalidKeyException, SignatureException {

        assert(proof != null);
        
        if (proof.signature() == null) {
            return false;
        }

        var algorithm = proof.signature().algorithm();
        
        var methodResolver = methodResolvers.get(proof.type());
        
        var publicKey = methodResolver.resolve(proof, algorithm);

        return verify(proof, publicKey);
    }

    public boolean verify(Proof proof, byte[] publicKey) throws InvalidKeyException, SignatureException {

        assert(proof != null);
        
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
        
        Map<String, MethodResolver> methodResolvers;
        
        private Builder() {
            this.methodResolvers = new HashMap<>();
        }
        
        public Builder accept(String proofType, MethodResolver resolver) {
            methodResolvers.put(proofType, resolver);
            return this;
        }
        
        public ProofVerifier build() {
            return new ProofVerifier(methodResolvers, null);
        }
    }
}
