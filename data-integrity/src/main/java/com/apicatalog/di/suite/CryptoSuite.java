package com.apicatalog.di.suite;

import com.apicatalog.trust.Proof;
import com.apicatalog.trust.Signature;
import com.apicatalog.trust.document.DigestiblePayload;

public interface CryptoSuite {

    String id();

    String algorithm();

    String c14n();

    String digest();

    String encode(Signature signature);

    byte[] decode(String value);

    Signature createSignature(String value, Proof proof, DigestiblePayload document);
}
