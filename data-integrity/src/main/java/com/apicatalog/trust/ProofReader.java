package com.apicatalog.trust;

import com.apicatalog.trust.document.CanonicalPayload;

/**
 * A factory interface for constructing cryptographic proofs from a
 * canonicalized document payload.
 * 
 */
public interface ProofReader<T extends Proof> {

//    /**
//     * Reads and constructs a proof instance from the provided canonical payload.
//     * 
//     * @param payload the digestible payload containing the canonical bytes and
//     *                transformation algorithm
//     * 
//     * @return the constructed proof instance
//     */
//    default T read(CanonicalPayload payload) {
//        return read(payload.c14n(), payload.canonicalPayload());
//    }
//
//    /**
//     * Reads and constructs a proof instance from explicit canonical components.
//     * 
//     * @param c14n             the canonicalization algorithm identifier
//     * @param canonicalPayload the canonical byte array
//     * 
//     * @return the constructed proof instance
//     */
//    T read(String c14n, byte[] canonicalPayload);
}
