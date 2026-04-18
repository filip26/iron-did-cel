package com.apicatalog.cel.cache;

public interface StatusCache {

    void set(String eventEntryDigest, Object status);
    
    Object get(String eventEntryDigest);
    
}
