package com.apicatalog.trust;

import java.time.Instant;

import com.apicatalog.trust.document.DigestiblePayload;

public interface Proof extends DigestiblePayload {

    String type();

    /**
     * Retrieves the cryptographic signature associated with this proof. If a
     * signature is present, the proof is considered signed and its authenticity can
     * be verified against the canonical representation.
     *
     * @return the {@link Signature} object, or {@code null} if the proof is
     *         unsigned
     */
    Signature signature();

    String verificationMethod();

    String purpose();
    
    Instant created();
}
