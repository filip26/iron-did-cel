
import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Provides pre-built templates for canonical JSON and RDF Dataset
 * Canonicalization (RDFC) proofs, optimized for cryptographic hashing and
 * signing.
 */
public class Proof {

    private static final String[] JCS_PROOF_PARTS = new String[] {
            "{\"created\":\"",
            "\",\"cryptosuite\":\"",
            "\",\"nonce\":\"",
            "\",\"proofPurpose\":\"assertionMethod\",\"type\":\"DataIntegrityProof\",\"verificationMethod\":\"",
            "\"}" };

    private static final int JCS_PROOF_PARTS_LENGTH = Arrays.stream(JCS_PROOF_PARTS)
            .mapToInt(String::length)
            .sum();

    private final String cryptosuite;
    private final String created;
    private final String method;
    private final String nonce;

    private String signature;

    public Proof(String cryptosuite, String created, String method, String nonce) {
        this.cryptosuite = cryptosuite;
        this.created = created;
        this.method = method;
        this.nonce = nonce;
        this.signature = null;
    }

    /**
     * Builds the canonical JSON proof (JCS) for hashing/signing.
     *
     * @param proof
     * @return UTF-8 encoded JSON proof bytes
     */
    public final static byte[] toJcsByteArray(Proof proof) {
        return new StringBuilder(JCS_PROOF_PARTS_LENGTH
                + proof.cryptosuite.length()
                + proof.created.length()
                + proof.nonce.length()
                + proof.method.length())
                .append(JCS_PROOF_PARTS[0]).append(proof.created)
                .append(JCS_PROOF_PARTS[1]).append(proof.cryptosuite)
                .append(JCS_PROOF_PARTS[2]).append(proof.nonce)
                .append(JCS_PROOF_PARTS[3]).append(proof.method)
                .append(JCS_PROOF_PARTS[4])
                .toString()
                .getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Builds the deterministic N-Quads representation of a DataIntegrityProof blank
     * node for RDF Dataset Canonicalization (RDFC).
     *
     * <p>
     * The returned value is UTF-8 encoded and suitable for hashing or signing. The
     * output strictly follows N-Quads syntax and is deterministic for the supplied
     * values.
     * </p>
     * 
     * @param proof
     * @return UTF-8 encoded canonical N-Quads proof representation
     */
    public final static byte[] toRdfcByteArray(Proof proof) {
        return new StringBuilder(420
                + proof.cryptosuite.length()
                + proof.created.length()
                + proof.method.length()
                + proof.nonce.length())
                .append("_:c14n0 <http://purl.org/dc/terms/created> \"")
                .append(proof.created)
                .append("\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .\n_:c14n0 <https://w3id.org/security#cryptosuite> \"")
                .append(proof.cryptosuite)
                .append("\"^^<https://w3id.org/security#cryptosuiteString> .\n_:c14n0 <https://w3id.org/security#nonce> \"")
                .append(proof.nonce)
                .append("\" .\n_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .\n_:c14n0 <https://w3id.org/security#verificationMethod> <")
                .append(proof.method)
                .append("> .\n")
                .toString()
                .getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Writes the complete JSON proof including a cryptographic signature if
     * present.
     *
     * @param writer
     */
    public void write(Writer writer) throws IOException {
        writer.write(JCS_PROOF_PARTS[0]);
        writer.write(created);

        writer.write(JCS_PROOF_PARTS[1]);
        writer.write(cryptosuite);

        writer.write(JCS_PROOF_PARTS[2]);
        writer.write(nonce);
        writer.write(JCS_PROOF_PARTS[3]);
        writer.write(method);

        if (signature != null) {
            writer.write("\",\"proofValue\":\"");
            writer.write(signature);
        }
        writer.write(JCS_PROOF_PARTS[4]);
    }

    public Proof signature(String signature) {
        this.signature = signature;
        return this;
    }
}
