package com.apicatalog.trust;

@FunctionalInterface
public interface MethodResolver {

    byte[] resolve(Proof proof);
    
}
