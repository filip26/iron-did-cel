package com.apicatalog.di;

import java.security.SignatureException;
import java.util.Map;

import com.apicatalog.crypto.AsymmetricSigner;

public interface ProofDraft {

    Proof sign(AsymmetricSigner signer, Map<String, Object> document) throws SignatureException;

    Proof sign(AsymmetricSigner signer, byte[] canonicalData) throws SignatureException;

    Proof unsigned();

}
