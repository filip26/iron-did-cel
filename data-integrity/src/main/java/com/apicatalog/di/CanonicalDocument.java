package com.apicatalog.di;

public interface CanonicalDocument {

    byte[] payload();

    String c14n();
    
}
