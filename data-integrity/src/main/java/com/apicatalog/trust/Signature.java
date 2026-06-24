package com.apicatalog.trust;

import com.apicatalog.trust.document.CanonicalPayload;

public interface Signature {

    CanonicalPayload document();

    Proof proof();

    byte[] toByteArray();

    String algorithm();
}
