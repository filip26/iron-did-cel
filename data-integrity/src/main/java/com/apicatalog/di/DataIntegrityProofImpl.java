package com.apicatalog.di;

import java.time.Instant;
import java.util.Collection;

import com.apicatalog.iron.Signature;

class DataIntegrityProofImpl implements DataIntegrityProof {

    byte[] payload;
    CryptoSuite cryptosuite;
    Instant created;
    Instant expires;
    DataIntegritySignature signature;

    @Override
    public String type() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String id() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public CryptoSuite cryptosuite() {
        return cryptosuite;
    }

    @Override
    public String purpose() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Instant created() {
        return created;
    }

    @Override
    public Instant expires() {
        return expires;
    }

    @Override
    public Collection<String> domain() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String challenge() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String nonce() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String previousProof() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Signature signature() {
        return signature;
    }

    @Override
    public String verificationMethod() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public byte[] canonicalPayload() {
        return payload;
    }

    @Override
    public String c14n() {
        return cryptosuite.c14n;
    }

}
