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
    
    /**
     * Returns the canonical, normalized byte representation of the proof, excluding
     * the signature. This payload serves as the deterministic input for
     * cryptographic operations.
     *
     * @return the byte array representing the canonical payload
     */
    byte[] canonicalPayload();
    
}
