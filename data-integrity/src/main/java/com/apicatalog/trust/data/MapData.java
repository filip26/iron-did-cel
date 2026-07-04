package com.apicatalog.trust.data;

import java.util.Map;
import java.util.Objects;

/**
 * A container for data that has been prepared for cryptographic
 * operations.
 *
 * <p>
 * This implementation maintains the original source document, the canonical
 * byte representation, and the canonicalization algorithm identifier. It
 * supports optional, thread-safe caching of cryptographic digests.
 * </p>
 */
public class MapData extends GenericPayload {

    private final Map<String, ?> data;

    /**
     * Constructs a new {@code MapData}.
     *
     * @param data         the original source document map
     * @param canonicalPayload the canonical byte array of the document
     * @param c14n             the canonicalization algorithm identifier
     * @throws NullPointerException if any argument is null
     */
    public MapData(Map<String, ?> data, byte[] canonicalPayload, String c14n) {
        Objects.requireNonNull(data, "document must not be null");

        super(canonicalPayload, c14n);

        this.data = Map.copyOf(data);
    }

    /**
     * Returns an unmodifiable view of the original source data.
     *
     * @return the source map
     */
    public Map<String, ?> data() {
        return data;
    }

}