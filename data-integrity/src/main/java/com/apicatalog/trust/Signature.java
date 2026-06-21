package com.apicatalog.trust;

public interface Signature {

    CanonicalPayload document();

    Proof proof();

    byte[] toByteArray();

    String algorithm();
}
