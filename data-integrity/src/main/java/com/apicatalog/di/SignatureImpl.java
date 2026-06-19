package com.apicatalog.di;

import java.security.InvalidKeyException;
import java.security.SignatureException;

import com.apicatalog.crypto.AsymmetricVerifier;

public class SignatureImpl implements Signature {

    byte[] digest;
    byte[] signature;
    DataIntegrityProofImpl proof;
    CanonicalDocument document;

    @Override
    public boolean verify(AsymmetricVerifier verifier, byte[] publicKey)
            throws InvalidKeyException, SignatureException {
        return verifier.verify(publicKey, digest, signature);
    }

    @Override
    public byte[] toByteArray() {
        return signature;
    }
    
    @Override
    public byte[] digest() {
        return digest;
    }

    @Override
    public CanonicalDocument document() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Proof proof() {
        // TODO Auto-generated method stub
        return null;
    }
}
