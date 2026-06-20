package com.apicatalog.di;

@FunctionalInterface
public interface MethodResolver {

    byte[] resolve(String method, String purpose, String algorithm);
    
}
