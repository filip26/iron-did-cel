package com.apicatalog.cel.cache;

public interface EventEntryStatusCache {

    //TODO source? verification datetime? witness verification policy name?
    void set(String eventEntryDigest, boolean verified);
    
    boolean isVerified(String eventEntryDigest);
    
}
