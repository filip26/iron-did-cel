package com.apicatalog.iron;

public interface Proof extends CanonicalDocument {

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
}
