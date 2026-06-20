package com.apicatalog.iron;

import java.security.InvalidKeyException;
import java.security.SignatureException;

public class Verifier {

    //TODO returns builder
    public static Object newVerifier() {

        return null;
    }
    
    public boolean verify(Proof proof) {
        
        if (proof.signature() == null) {
            return false;
        }
        
        var method = proof.verificationMethod();
        var algorithm = proof.signature().algorithm();
        
        //TODO
        return false;
    }
    
    public boolean verify(Proof proof, byte[] publicKey)
            throws InvalidKeyException, SignatureException {


        if (proof.signature() == null) {
            return false;
        }
        
        proof.signature().verify(null, publicKey);

        // TODO
        return false;
    }

}
