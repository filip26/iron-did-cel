package com.apicatalog.di.signature;

@FunctionalInterface
public interface SignatureEncoder {

    String encode(byte[] signature);
    
}
