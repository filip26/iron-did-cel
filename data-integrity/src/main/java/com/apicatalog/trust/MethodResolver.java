package com.apicatalog.trust;

@FunctionalInterface
public interface MethodResolver {

    byte[] resolve(String method, String purpose, String algorithm);
    
}
