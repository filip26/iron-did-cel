package com.apicatalog.di;

import java.time.Instant;
import java.util.Collection;

import com.apicatalog.iron.Proof;

public interface DataIntegrityProof extends Proof {

    String id();

    CryptoSuite cryptosuite();
    
    String verificationMethod();
    
    String purpose();
    
    Instant created();
    
    Instant expires();
    
    Collection<String> domain();
    
    String challenge();
    
    String nonce();

    String previousProof();    
}
