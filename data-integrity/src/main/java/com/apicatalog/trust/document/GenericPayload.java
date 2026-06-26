package com.apicatalog.trust.document;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A generic container for data that has been prepared for cryptographic
 * operations.
 *
 * <p>
 * This implementation maintains the canonical byte representation, and the
 * canonicalization algorithm identifier. It supports optional, thread-safe
 * caching of cryptographic digests.
 * </p>
 */
public class GenericPayload implements DigestiblePayload {

    private final byte[] canonicalPayload;
    private final String c14n;

    /**
     * Lazily initialized cache for cryptographic digests.
     */
    private volatile Map<String, byte[]> digests;

    /**
     * Constructs a new {@code GenericPayload}.
     *
     * @param canonicalPayload the canonical byte array of the document
     * @param c14n             the canonicalization algorithm identifier
     * @throws NullPointerException if any argument is null
     */
    public GenericPayload(byte[] canonicalPayload, String c14n) {
        Objects.requireNonNull(canonicalPayload, "canonicalPayload must not be null");
        Objects.requireNonNull(c14n, "c14n must not be null");

        super();

        this.canonicalPayload = canonicalPayload.clone();
        this.c14n = c14n;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Returns a defensive copy of the canonical bytes.
     * </p>
     */
    @Override
    public byte[] canonicalPayload() {
        return canonicalPayload.clone();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String c14n() {
        return c14n;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Stores the provided digest in a thread-safe cache.
     * </p>
     *
     * @param algorithm the cryptographic hash algorithm
     * @param value     the computed digest value to cache
     */
    @Override
    public void digest(String algorithm, byte[] value) {
        if (value == null) {
            return;
        }

        if (digests == null) {
            synchronized (this) {
                if (digests == null) {
                    digests = new ConcurrentHashMap<>(2);
                }
            }
        }
        digests.put(algorithm, value.clone());
    }

    /**
     * {@inheritDoc}
     * <p>
     * Retrieves a defensive copy of the cached digest if available.
     * </p>
     *
     * @param algorithm the cryptographic hash algorithm
     * @return the cached digest, or {@code null} if not found
     */
    @Override
    public byte[] digest(String algorithm) {
        if (digests == null) {
            return null;
        }

        byte[] value = digests.get(algorithm);
        return value != null ? value.clone() : null;
    }

}
