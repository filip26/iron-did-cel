package com.apicatalog.di;

import java.time.Instant;
import java.util.Collection;

class DataIntegrityProofImpl implements DataIntegrityProof {

    byte[] payload;
    
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
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String purpose() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Instant created() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Instant expires() {
        // TODO Auto-generated method stub
        return null;
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
    public byte[] canonicalPayload() {
        return payload;
    }

    @Override
    public Signature signature() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String verificationMethod() {
        // TODO Auto-generated method stub
        return null;
    }

}
