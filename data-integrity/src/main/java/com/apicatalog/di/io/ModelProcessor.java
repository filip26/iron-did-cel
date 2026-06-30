package com.apicatalog.di.io;

import com.apicatalog.trust.Proof;

public interface ModelProcessor {


    
//    Collection<String> contexts();
//    
//    Function<String, DigestiblePayload> documents();
////    public Set<String> getModes() {
////
////    }
//
    ProofCursor createProofCursor();
//    
//    ProofCursor createProofCursor(Map<String, V> adapters?);

boolean hasNext();

void next();

Proof proof();
    
//    ProofCursor createProofCursor(Collection<String> contexts, Map<String, Object> document);
}
