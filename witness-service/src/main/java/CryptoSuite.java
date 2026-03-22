
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.function.Function;

import com.apicatalog.multibase.Multibase;
import com.google.cloud.kms.v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm;

/**
 * Represents a cryptographic suite that supports canonicalization (JCS/RDFC),
 * digest computation, and signing.
 *
 * <p>
 * This class provides a high-level API for creating canonical JSON or RDF
 * proofs/documents, computing concatenated hashes, and producing signed proofs
 * with a secure nonce.
 * </p>
 */
public final class CryptoSuite {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final String suiteName;
    private final int keyLength;

    private final Function<byte[], byte[]> signer;

    private final Function<String, byte[]> documentC14n;
    private final Function<Proof, byte[]> proofC14n;

    private final String digestName;
    private final Function<byte[], String> signatureEncoder;

    public CryptoSuite(
            String name,
            int keyLength,
            Function<byte[], byte[]> signer,
            Function<String, byte[]> documentC14n,
            Function<Proof, byte[]> proofC14n,
            String digestName,
            Function<byte[], String> signatureEncoder) {
        this.suiteName = name;
        this.keyLength = keyLength;
        this.signer = signer;
        this.documentC14n = documentC14n;
        this.proofC14n = proofC14n;
        this.digestName = digestName;
        this.signatureEncoder = signatureEncoder;
    }

    /**
     * Creates a new {@link CryptoSuite} instance for the specified KMS algorithm
     * and canonicalization method.
     *
     * @param algorithm        the KMS key algorithm
     * @param c14n             the canonicalization method ("JCS" or "RDFC")
     * @param asymmetricSigner a function that performs asymmetric signing
     * @return a configured {@link CryptoSuite} instance
     * @throws IllegalStateException if the canonicalization method or algorithm is
     *                               unsupported
     */
    public static CryptoSuite newSuite(
            CryptoKeyVersionAlgorithm algorithm,
            String c14n,
            Function<byte[], byte[]> asymmetricSigner) {

        final Function<String, byte[]> documentC14n;
        final Function<Proof, byte[]> proofC14n;

        switch (c14n) {
        case "JCS":
            documentC14n = Document::toJcsByteArray;
            proofC14n = Proof::toJcsByteArray;
            break;

        case "RDFC":
            documentC14n = Document::toRdfcByteArray;
            proofC14n = Proof::toRdfcByteArray;
            break;

        default:
            throw new IllegalStateException("Unsupported C14N [" + c14n + "]");
        }

        return switch (algorithm) {
        case EC_SIGN_P256_SHA256 -> new CryptoSuite(
                "ecdsa-" + c14n.toLowerCase() + "-2019",
                32,
                asymmetricSigner,
                documentC14n,
                proofC14n,
                "SHA-256",
                Multibase.BASE_58_BTC::encode);

        case EC_SIGN_P384_SHA384 -> new CryptoSuite(
                "ecdsa-" + c14n.toLowerCase() + "-2019",
                48,
                asymmetricSigner,
                documentC14n,
                proofC14n,
                "SHA-384",
                Multibase.BASE_58_BTC::encode);

        case EC_SIGN_ED25519 -> new CryptoSuite(
                "eddsa-" + c14n.toLowerCase() + "-2022",
                32,
                asymmetricSigner,
                documentC14n,
                proofC14n,
                "SHA-256",
                Multibase.BASE_58_BTC::encode);

        case PQ_SIGN_SLH_DSA_SHA2_128S -> new CryptoSuite(
                "slhdsa128-" + c14n.toLowerCase() + "-2024",
                32,
                asymmetricSigner,
                documentC14n,
                proofC14n,
                "SHA-256",
                Multibase.BASE_64_URL::encode);

        case PQ_SIGN_ML_DSA_44 -> new CryptoSuite(
                "mldsa44-" + c14n.toLowerCase() + "-2024",
                1312,
                asymmetricSigner,
                documentC14n,
                proofC14n,
                "SHA-256",
                Multibase.BASE_64_URL::encode);

        default ->
            throw new IllegalStateException("Unsupported KMS Key Algorithm [" + algorithm + "]");
        };
    }

    /**
     * Signs a canonicalized document digest using this cryptosuite.
     *
     * <p>
     * This method generates a deterministic proof with timestamp and nonce,
     * computes the concatenated hash of the canonical document and proof, signs it,
     * and returns a proof including the signature encoded in Base58 BTC.
     * </p>
     *
     * @param digest the canonicalized document digest (multibase string)
     * @param method the verification method URI
     * @return a proof including the signature
     */
    public Proof sign(String digest, String method) {

        var canonicalDocument = documentC14n.apply(digest);

        var proof = new Proof(
                suiteName, 
                Instant.now().truncatedTo(ChronoUnit.SECONDS).toString(), 
                method, 
                generateNonce(32));
        
        var canonicalProof = proofC14n.apply(proof);

        try {
            var hash = hash(digestName, canonicalDocument, canonicalProof);

            var signature = signer.apply(hash);

            return proof.signature(signatureEncoder.apply(signature));

        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Computes H(canonicalProof) || H(canonicalDocument) using the specified digest
     * algorithm.
     *
     * @param algorithm         the hash algorithm (e.g. "SHA-256")
     * @param canonicalDocument the canonicalized document bytes
     * @param canonicalProof    the canonicalized proof bytes
     * @return concatenation of H(canonicalProof) and H(canonicalDocument)
     * @throws NoSuchAlgorithmException if the algorithm is unavailable
     */
    private static byte[] hash(String algorithm,
            byte[] canonicalDocument,
            byte[] canonicalProof)
            throws NoSuchAlgorithmException {

        var md = MessageDigest.getInstance(algorithm);

        md.update(canonicalProof);
        var proofHash = md.digest();

        md.update(canonicalDocument);
        var docHash = md.digest();

        var result = new byte[proofHash.length + docHash.length];
        System.arraycopy(proofHash, 0, result, 0, proofHash.length);
        System.arraycopy(docHash, 0, result, proofHash.length, docHash.length);
        return result;
    }

    /**
     * Generates a cryptographically secure, URL-safe nonce.
     *
     * <p>
     * The returned value is a Base64 URL-encoded string without padding, making it
     * safe for use in JSON documents, URLs, HTTP headers, and cryptographic proofs
     * without additional escaping.
     * </p>
     *
     * @param bytesLength the number of random bytes to generate
     * @return a URL-safe, unpadded Base64-encoded nonce string
     */
    private static String generateNonce(int bytesLength) {

        final var nonce = new byte[bytesLength];

        SECURE_RANDOM.nextBytes(nonce);

        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(nonce);
    }

    public String name() {
        return suiteName;
    }

    public int keyLength() {
        return keyLength;
    }
}
