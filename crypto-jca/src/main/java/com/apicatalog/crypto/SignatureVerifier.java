package com.apicatalog.crypto;

import java.security.InvalidKeyException;
import java.security.SignatureException;

@FunctionalInterface
public interface SignatureVerifier {

    /**
     * 
     * @param publicKey the raw public key
     * @param data      the data to be verified
     * @param signature the signature to be verified
     * @return <code>true</code> if the signature was verified, <code>false</code>
     *         if not
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    boolean verify(byte[] publicKey, byte[] data, byte[] signature) throws InvalidKeyException, SignatureException;

}
