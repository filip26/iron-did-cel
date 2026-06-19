package com.apicatalog.di;

public interface Proof {

    String type();
    
    /**
     * Returns the canonical, normalized byte representation of the proof, excluding
     * the signature. This payload serves as the deterministic input for
     * cryptographic operations.
     *
     * @return the byte array representing the canonical payload
     */
    byte[] canonicalPayload();

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
