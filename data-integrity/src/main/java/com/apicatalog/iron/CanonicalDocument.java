package com.apicatalog.iron;

public interface CanonicalDocument {

    byte[] payload();

    String c14n();
    
}
