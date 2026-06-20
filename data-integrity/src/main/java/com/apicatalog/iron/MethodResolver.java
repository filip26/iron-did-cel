package com.apicatalog.iron;

@FunctionalInterface
public interface MethodResolver {

    byte[] resolve(String method, String purpose, String algorithm);
    
}
