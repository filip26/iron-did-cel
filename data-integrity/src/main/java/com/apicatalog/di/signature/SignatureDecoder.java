package com.apicatalog.di.signature;

@FunctionalInterface
public interface SignatureDecoder {

    byte[] decode(String signature);
    
}
