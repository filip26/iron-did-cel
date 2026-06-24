package com.apicatalog.trust.document;

public interface CanonicalPayload {

    /**
     * Returns the canonical, normalized byte representation. This payload serves as
     * the deterministic input for cryptographic operations.
     *
     * @return the byte array representing the canonical document
     */

    byte[] canonicalPayload();

    /***
     * Returns the algorithm used to canonize the payload.
     * 
     * @return the c14n algorithm name
     */
    String c14n();

}
