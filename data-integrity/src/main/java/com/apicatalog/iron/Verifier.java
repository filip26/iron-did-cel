package com.apicatalog.iron;

import java.security.InvalidKeyException;
import java.security.SignatureException;

import com.apicatalog.di.DataIntegrityProof;

public class Verifier {

    //TODO returns builder
    public static Object newVerifier() {

        return null;
    }
    public boolean verify(DataIntegrityProof proof, byte[] publicKey)
            throws InvalidKeyException, SignatureException {

        proof.signature().verify(null, publicKey);

        // TODO
        return false;
    }

}
