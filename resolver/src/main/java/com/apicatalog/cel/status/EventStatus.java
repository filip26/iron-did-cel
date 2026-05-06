package com.apicatalog.cel.status;

public interface EventStatus {

    void set(String eventEntryDigest, Object status);
    
    Object get(String eventEntryDigest);
    
}
