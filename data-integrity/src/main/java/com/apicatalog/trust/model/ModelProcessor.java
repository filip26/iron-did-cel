package com.apicatalog.trust.model;

import com.apicatalog.trust.Proof;
import com.apicatalog.trust.proof.ProofCursor;

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
