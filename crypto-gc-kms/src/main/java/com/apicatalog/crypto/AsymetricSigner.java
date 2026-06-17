package com.apicatalog.crypto;

import java.security.InvalidKeyException;
import java.security.SignatureException;

@FunctionalInterface
public interface AsymetricSigner {

    /**
     * 
     * @param data to be signed
     * @return the signature
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    byte[] sign(byte[] data) throws InvalidKeyException, SignatureException;

}
