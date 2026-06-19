package com.apicatalog.di;

import java.security.SignatureException;
import java.time.Instant;

import com.apicatalog.crypto.AsymmetricSigner;

public interface ProofDraft {

    
    ProofDraft created(Instant created);
    
    Proof sign(AsymmetricSigner signer, byte[] canonicalData) throws SignatureException;
    Proof unsigned();
    
}
