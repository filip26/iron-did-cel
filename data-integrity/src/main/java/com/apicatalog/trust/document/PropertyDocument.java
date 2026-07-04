package com.apicatalog.trust.document;

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
public class PropertyDocument extends GenericPayload {

    private final Map<String, ?> document;

    /**
     * Constructs a new {@code DigestibleDocument}.
     *
     * @param document         the original source document map
     * @param canonicalPayload the canonical byte array of the document
     * @param c14n             the canonicalization algorithm identifier
     * @throws NullPointerException if any argument is null
     */
    public PropertyDocument(Map<String, ?> document, byte[] canonicalPayload, String c14n) {
        Objects.requireNonNull(document, "document must not be null");

        super(canonicalPayload, c14n);

        this.document = Map.copyOf(document);
    }

    /**
     * Returns an unmodifiable view of the original source document.
     *
     * @return the source map
     */
    public Map<String, ?> document() {
        return document;
    }

}