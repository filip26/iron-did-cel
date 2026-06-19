package com.apicatalog.iron;

public interface CanonicalDocument {

    /**
     * Returns the canonical, normalized byte representation of the document. This
     * payload serves as the deterministic input for cryptographic operations.
     *
     * @return the byte array representing the canonical document
     */

    byte[] canonicalPayload();

    /***
     * Returns the algorithm used to canonize the document.
     * 
     * @return the c14n algorithm name
     */
    String c14n();

}
