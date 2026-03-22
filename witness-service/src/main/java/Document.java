
import java.nio.charset.StandardCharsets;

/**
 * Provides pre-built templates for canonical JSON and RDF Dataset
 * Canonicalization (RDFC) documents, optimized for cryptographic
 * hashing and signing.
 */
public class Document {

    private Document() {
        /* prevent instantiation */ }

    /**
     * Builds the canonical JSON document (JCS) with the given digest.
     *
     * @param digest multibase digest string
     * @return UTF-8 encoded JSON document bytes
     */
    public static final byte[] toJcsByteArray(String digest) {
        return new StringBuilder(22 + digest.length())
                .append("{\"digestMultibase\":\"")
                .append(digest)
                .append("\"}")
                .toString()
                .getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Builds the canonical N-Quads representation of a digest for RDF Dataset
     * Canonicalization (RDFC).
     *
     * <p>
     * The returned value is UTF-8 encoded and suitable for hashing or signing. The
     * output strictly follows N-Quads syntax, with a blank node subject and a typed
     * literal for the digest.
     * </p>
     *
     * @param digest the multibase digest string
     * @return UTF-8 encoded canonical N-Quads representation of the digest
     */
    public static final byte[] toRdfcByteArray(String digest) {
        return new StringBuilder(18 + digest.length())
                .append("_:c14n0 <https://w3id.org/security#digestMultibase> \"")
                .append(digest)
                .append("\"^^<https://w3id.org/security#multibase> .\n")
                .toString()
                .getBytes(StandardCharsets.UTF_8);
    }
}
