package com.apicatalog.iron;

import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Map;

import com.apicatalog.crypto.AsymmetricVerifier;

public class ProofVerifier {

    MethodResolver methodResolvers;
    Map<String, AsymmetricVerifier> verifiers;

    // TODO returns builder
    public static Object newVerifier() {

        return null;
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

        var signer = verifiers.get(proof.signature().algorithm());

        return proof.signature().verify(signer, publicKey);
    }
}
