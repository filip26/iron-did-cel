package com.apicatalog.di.signature;

import com.apicatalog.di.c14n.CanonicalPayload;
import com.apicatalog.di.proof.Proof;

public interface Signature {

    CanonicalPayload document();

    Proof proof();

    byte[] toByteArray();

    String algorithm();
}
