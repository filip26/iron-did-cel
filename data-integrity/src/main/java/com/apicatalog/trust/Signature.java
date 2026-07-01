package com.apicatalog.trust;

import com.apicatalog.trust.document.DigestiblePayload;

public interface Signature {

    DigestiblePayload document();

    Proof proof();

    byte[] toByteArray();

    String algorithm();
}
