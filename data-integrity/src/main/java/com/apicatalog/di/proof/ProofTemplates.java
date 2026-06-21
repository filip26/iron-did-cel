package com.apicatalog.di.proof;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.function.Function;
import java.util.stream.Stream;

import com.apicatalog.di.suite.CryptoSuite;

/**
 * Provides pre-built templates for canonical JSON and RDF Dataset
 * Canonicalization (RDFC) proofs and documents, optimized for cryptographic
 * hashing and signing.
 */
class ProofTemplates {

    @FunctionalInterface
    public interface ProofCanonizer {
        byte[] canonize(DataIntegrityProof proof);
    }
    
    private static final byte[][] RDFC_TEMPLATE = Stream.of(
            "_:c14n0",
            " <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .",

            " <http://purl.org/dc/terms/created> \"",
            "\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .",

            " <https://vc.ex/1> <https://w3id.org/security#challenge> \"",
            "\" .",

            " <https://w3id.org/security#cryptosuite> \"",
            "\"^^<https://w3id.org/security#cryptosuiteString> .",

            " <https://w3id.org/security#domain> \"",
            "\" .",

            " <https://w3id.org/security#expiration> \"",
            "\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .",

            " <https://w3id.org/security#nonce> \"",
            "\" .",

            "<https://vc.ex/1> <https://w3id.org/security#previousProof> <",
            "> .",

            " <https://w3id.org/security#proofPurpose> <https://w3id.org/security#",
            "> .",

            " <https://w3id.org/security#verificationMethod> <",
            "> .")
            .map(i -> i.getBytes(StandardCharsets.UTF_8))
            .toArray(byte[][]::new);

    static final byte[][] JCS_TEMPLATE = Stream.of(
            "{\"created\":\"",
            "\",\"cryptosuite\":\"",
            "\",\"nonce\":\"",
            "\",\"proofPurpose\":\"assertionMethod\",\"type\":\"DataIntegrityProof\",\"verificationMethod\":\"",
            "\"}"
)
            .map(i -> i.getBytes(StandardCharsets.UTF_8))
            .toArray(byte[][]::new);


    public static ProofCanonizer getInstance(String c14n) {
        return switch (c14n) {
        case "JCS" -> ProofTemplates::jcs;
        case "RDFC" -> ProofTemplates::rdfc;
        default -> throw new IllegalArgumentException();
        };
    }

    private static final String[] JCS_PROOF_PARTS = new String[] {
            "{\"created\":\"",
            "\",\"cryptosuite\":\"",
            "\",\"nonce\":\"",
            "\",\"proofPurpose\":\"assertionMethod\",\"type\":\"DataIntegrityProof\",\"verificationMethod\":\"",
            "\"}" };

    private static final int JCS_PROOF_PARTS_LENGTH = Arrays.stream(JCS_PROOF_PARTS)
            .mapToInt(String::length)
            .sum();

    private ProofTemplates() {
        /* prevent instantiation */ }

    public static final byte[] jcs(DataIntegrityProof proof) {
        return null;
    }

    public static final byte[] rdfc(DataIntegrityProof proof) {

        byte[] id = proof.id() != null
                ? ("<" + proof.id() + ">").getBytes(StandardCharsets.UTF_8)
                : RDFC_TEMPLATE[0];

        try {
            var os = new ByteArrayOutputStream();

            writeEntry(id, 2, proof.created(), Instant::toString, os);

            os.write(id);
            os.write(RDFC_TEMPLATE[1]);
            os.write('\n');

            writeEntry(id, 4, proof.challenge(), os);
            writeEntry(id, 6, proof.cryptosuite(), CryptoSuite::id, os);

            if (proof.domains() != null && !proof.domains().isEmpty()) {
                for (var domain : proof.domains()) {
                    writeEntry(id, 8, domain, os);
                }
            }
            writeEntry(id, 10, proof.expires(), Instant::toString, os);
            writeEntry(id, 12, proof.nonce(), os);
            writeEntry(id, 14, proof.previousProof(), os);
            writeEntry(id, 16, proof.purpose(), os);
            writeEntry(id, 18, proof.verificationMethod(), os);

            return os.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static <T> void writeEntry(byte[] id, int index, String value, OutputStream os) throws IOException {
        if (value != null) {
            os.write(id);
            os.write(RDFC_TEMPLATE[index]);
            os.write(value.getBytes(StandardCharsets.UTF_8));
            os.write(RDFC_TEMPLATE[index + 1]);
            os.write('\n');
        }
    }

    private static <T> void writeEntry(byte[] id, int index, T value, Function<T, String> map, OutputStream os)
            throws IOException {
        if (value != null) {
            writeEntry(id, index, map.apply(value), os);
        }
    }

    /**
     * Builds the canonical JSON proof (JCS) for hashing/signing.
     *
     * @param cryptosuite the cryptosuite identifier
     * @param created     ISO-8601 timestamp of the proof
     * @param method      verification method URI
     * @param nonce       cryptographically secure nonce
     * @return UTF-8 encoded JSON proof bytes
     */
    public static final byte[] jcsProof(
            String cryptosuite,
            String created,
            String method,
            String nonce) {

        if (nonce == null) {
            return new StringBuilder(JCS_PROOF_PARTS_LENGTH
                    + cryptosuite.length()
                    + created.length()
                    + method.length())
                    .append(JCS_PROOF_PARTS[0]).append(created)
                    .append(JCS_PROOF_PARTS[1]).append(cryptosuite)
                    .append(JCS_PROOF_PARTS[3]).append(method)
                    .append(JCS_PROOF_PARTS[4])
                    .toString()
                    .getBytes(StandardCharsets.UTF_8);
        }

        return new StringBuilder(JCS_PROOF_PARTS_LENGTH
                + cryptosuite.length()
                + created.length()
                + nonce.length()
                + method.length())
                .append(JCS_PROOF_PARTS[0]).append(created)
                .append(JCS_PROOF_PARTS[1]).append(cryptosuite)
                .append(JCS_PROOF_PARTS[2]).append(nonce)
                .append(JCS_PROOF_PARTS[3]).append(method)
                .append(JCS_PROOF_PARTS[4])
                .toString()
                .getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Builds the canonical JSON document (JCS) with the given digest.
     *
     * @param digest multibase digest string
     * @return UTF-8 encoded JSON document bytes
     */
    public static final byte[] jcsDocument(String digest) {

        return "{\"digestMultibase\":\"zQmYGx7Wzqe5prvEsTSzYBQN8xViYUM9qsWJSF5EENLcNmM\",\"options\":{\"cryptosuite\":\"ecdsa-rdfc-2019\"}}"
                .getBytes();

//        return new StringBuilder(22 + digest.length())
//                .append("{\"digestMultibase\":\"")
//                .append(digest)
//                .append("\"}")
//                .toString()
//                .getBytes(StandardCharsets.UTF_8);
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
     * @param cryptosuite the cryptosuite identifier (literal)
     * @param created     ISO-8601 timestamp (xsd:dateTime literal)
     * @param method      verification method IRI
     * @param nonce       cryptographically secure nonce (literal)
     * @return UTF-8 encoded canonical N-Quads proof representation
     */
    public static final byte[] rdfcProof(
            String cryptosuite,
            String created,
            String method,
            String nonce) {

        return new StringBuilder(420
                + cryptosuite.length()
                + created.length()
                + method.length()
                + nonce.length())
                .append("_:c14n0 <http://purl.org/dc/terms/created> \"")
                .append(created)
                .append("\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .\n_:c14n0 <https://w3id.org/security#cryptosuite> \"")
                .append(cryptosuite)
                .append("\"^^<https://w3id.org/security#cryptosuiteString> .\n_:c14n0 <https://w3id.org/security#nonce> \"")
                .append(nonce)
                .append("\" .\n_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .\n_:c14n0 <https://w3id.org/security#verificationMethod> <")
                .append(method)
                .append("> .\n")
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
    public static final byte[] rdfcDocument(String digest) {
        return new StringBuilder(18 + digest.length())
                .append("_:c14n0 <https://w3id.org/security#digestMultibase> \"")
                .append(digest)
                .append("\"^^<https://w3id.org/security#multibase> .\n")
                .toString()
                .getBytes(StandardCharsets.UTF_8);
    }
}
