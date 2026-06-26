package com.apicatalog.trust.document;

/**
 * Represents a payload that has been transformed into a canonical byte
 * representation and is capable of storing cryptographic digests.
 *
 * This interface is utilized within a cryptographic pipeline to hold the
 * deterministic bytes required for hashing, while acting as a stateful registry
 * for the resulting digest values.
 */
public interface DigestiblePayload {

    /**
     * Returns the canonical, normalized byte representation. This payload serves as
     * the deterministic input for cryptographic operations.
     *
     * @return the byte array representing the canonical document
     */

    byte[] canonicalPayload();

    /**
     * Returns the algorithm used to canonicalize the payload.
     * 
     * @return the canonicalization (c14n) algorithm identifier or name
     */
    String c14n();

    /**
     * Adds, or replaces an existing, digest value for the canonical payload.
     * 
     * @param algorithm the cryptographic hash algorithm used to generate the digest
     * @param value     the computed digest value
     */
    default void digest(String algorithm, byte[] value) {
        // optional, an implementation might ignore digest caching and re-use
    }

    /**
     * Retrieves the digest value associated with the specified algorithm.
     * 
     * @param algorithm the cryptographic hash algorithm
     * @return the digest value, or null if caching is ignored or no digest exists
     */
    default byte[] digest(String algorithm) {
        // optional, an implementation might ignore digest caching and re-use
        return null;
    }
}
