package com.apicatalog.di;

import java.security.InvalidKeyException;
import java.security.SignatureException;

import com.apicatalog.crypto.AsymmetricVerifier;
import com.apicatalog.iron.CanonicalDocument;
import com.apicatalog.iron.Proof;
import com.apicatalog.iron.Signature;

public class DataIntegritySignature implements Signature {

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
