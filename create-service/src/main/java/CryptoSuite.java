
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Map;
import java.util.function.Function;

import com.apicatalog.jcs.Jcs;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.tree.io.TreeIOException;
import com.apicatalog.tree.io.java.JavaAdapter;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.PublicKey;

/**
 * Represents a cryptographic suite that supports JCS canonicalization, digest
 * computation, and signing.
 *
 */
class CryptoSuite {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final String suiteName;
    private final int keyLength;

    private final AsymetricSigner signer;

    private final String digestName;
    private final Function<byte[], String> signatureEncoder;

    public CryptoSuite(
            String name,
            int keyLength,
            AsymetricSigner signer,
            String digestName,
            Function<byte[], String> signatureEncoder) {
        this.suiteName = name;
        this.keyLength = keyLength;
        this.signer = signer;
        this.digestName = digestName;
        this.signatureEncoder = signatureEncoder;
    }

    /**
     * Creates a new {@link CryptoSuite} instance for the specified KMS algorithm
     */
    public static CryptoSuite newSuite(
            PublicKey publicKey,
            KeyManagementServiceClient kms) {
        return switch (publicKey.getAlgorithm()) {
        case EC_SIGN_P256_SHA256 -> new CryptoSuite(
                "ecdsa-jcs-2019",
                32,
                KmsAsymericSigner.getInstance(publicKey, kms),
                "SHA-256",
                Multibase.BASE_58_BTC::encode);

        case EC_SIGN_P384_SHA384 -> new CryptoSuite(
                "ecdsa-jcs-2019",
                48,
                KmsAsymericSigner.getInstance(publicKey, kms),
                "SHA-384",
                Multibase.BASE_58_BTC::encode);

        case EC_SIGN_ED25519 -> new CryptoSuite(
                "eddsa-jcs-2022",
                32,
                KmsAsymericSigner.getInstance(publicKey, kms),
                "SHA-256",
                Multibase.BASE_58_BTC::encode);

        // PQ experiments
        case PQ_SIGN_SLH_DSA_SHA2_128S -> new CryptoSuite(
                "slhdsa128-jcs-2024",
                32,
                KmsAsymericSigner.getInstance(publicKey, kms),
                "SHA-256",
                Multibase.BASE_64_URL::encode);

        case PQ_SIGN_ML_DSA_44 -> new CryptoSuite(
                "mldsa44-jcs-2024",
                1312,
                KmsAsymericSigner.getInstance(publicKey, kms),
                "SHA-256",
                Multibase.BASE_64_URL::encode);

        case PQ_SIGN_ML_DSA_87 -> new CryptoSuite(
                "mldsa87-jcs-2024",
                2592,
                KmsAsymericSigner.getInstance(publicKey, kms),
                "SHA-512", // Level 5 security usually pairs with SHA-512
                Multibase.BASE_64_URL::encode);

        default ->
            throw new IllegalStateException("Unsupported KMS Key Algorithm [" + publicKey.getAlgorithm() + "]");
        };

    }

    public static CryptoSuite newInstance(String suitename, AsymetricSigner signer, int publicKeySize) {

        return switch (suitename) {
        case "ecdsa-jcs-2019" -> {
            if (publicKeySize == 32) {
                yield new CryptoSuite(
                        "ecdsa-jcs-2019",
                        32,
                        signer,
                        "SHA-256",
                        Multibase.BASE_58_BTC::encode);
            }
            if (publicKeySize == 48) {
                yield new CryptoSuite(
                        "ecdsa-jcs-2019",
                        48,
                        signer,
                        "SHA-384",
                        Multibase.BASE_58_BTC::encode);
            }

            throw new IllegalArgumentException("Unsupported key size for ecdsa ... TODO");
        }

//        : publicKeySize == 48
//        ?
// new CryptoSuite(
//                "ecdsa-jcs-2019",
//                48,
//                KmsAsymericSigner.getInstance(publicKey, kms),
//                "SHA-384",
//                Multibase.BASE_58_BTC::encode)
// : throw new IllegalArgumentException("Unsupported key size for ecdsa ... TODO");
//        }
//
//        case EC_SIGN_ED25519 -> new CryptoSuite(
//                "eddsa-jcs-2022",
//                32,
//                KmsAsymericSigner.getInstance(publicKey, kms),
//                "SHA-256",
//                Multibase.BASE_58_BTC::encode);
//
//        // PQ experiments
//        case PQ_SIGN_SLH_DSA_SHA2_128S -> new CryptoSuite(
//                "slhdsa128-jcs-2024",
//                32,
//                KmsAsymericSigner.getInstance(publicKey, kms),
//                "SHA-256",
//                Multibase.BASE_64_URL::encode);
//
//        case PQ_SIGN_ML_DSA_44 -> new CryptoSuite(
//                "mldsa44-jcs-2024",
//                1312,
//                KmsAsymericSigner.getInstance(publicKey, kms),
//                "SHA-256",
//                Multibase.BASE_64_URL::encode);
//
//        case PQ_SIGN_ML_DSA_87 -> new CryptoSuite(
//                "mldsa87-jcs-2024",
//                2592,
//                KmsAsymericSigner.getInstance(publicKey, kms),
//                "SHA-512", // Level 5 security usually pairs with SHA-512
//                Multibase.BASE_64_URL::encode);

        default ->
            throw new IllegalStateException("Unsupported cryptosuite [" + suitename + "]");
        };

    }

    public Map<String, String> sign(Map<String, Object> document, String method) throws SignatureException {

        try {
            var canonicalDocument = Jcs.canonize(document, JavaAdapter.instance())
                    .getBytes(StandardCharsets.UTF_8);

            var created = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
            var nonce = generateNonce(32);

            var canonicalProof = Templates.jcsProof(suiteName, created, method, nonce);

            var hash = hash(digestName, canonicalDocument, canonicalProof);

            var signature = signer.sign(hash);

            return Templates.jsonProof(
                    suiteName,
                    created,
                    method,
                    nonce,
                    signatureEncoder.apply(signature));

        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);

        } catch (TreeIOException e) {
            throw new IllegalArgumentException(e);
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
