package com.apicatalog.trust;

public interface Signature {

//    DigestiblePayload document();
//
//    Proof proof();

    byte[] toByteArray();

    String algorithm();
}
