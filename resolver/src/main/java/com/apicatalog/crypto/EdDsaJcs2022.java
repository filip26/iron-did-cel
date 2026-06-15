package com.apicatalog.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Map;
import java.util.function.Function;

import javax.xml.transform.Templates;

import com.apicatalog.jcs.Jcs;
import com.apicatalog.tree.io.TreeIOException;
import com.apicatalog.tree.io.java.JavaAdapter;

public class EdDsaJcs2022 implements CryptoSuite {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final String suiteName;
    private final int keyLength;

    private final Signer signer;

    private final KeyManagementServiceClient kms;
    private final String kmsKeyResource;

    private final String digestName;
    private final Function<byte[], String> signatureEncoder;

    public EdDsaJcs2022(
            String name,
            int keyLength,
            Signer signer,
            KeyManagementServiceClient kms,
            String kmsKeyResource,
            String digestName,
            Function<byte[], String> signatureEncoder) {
        this.suiteName = name;
        this.keyLength = keyLength;
        this.signer = signer;
        this.kms = kms;
        this.kmsKeyResource = kmsKeyResource;
        this.digestName = digestName;
        this.signatureEncoder = signatureEncoder;
    }

    @Override
    public Map<String, String> sign(Map<String, Object> document, String method) {

        try {
            var canonicalDocument = Jcs.canonize(document, JavaAdapter.instance())
                    .getBytes(StandardCharsets.UTF_8);

            var created = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
            var nonce = generateNonce(32);

            var canonicalProof = Templates.jcsProof(suiteName, created, method, nonce);

            var hash = hash(digestName, canonicalDocument, canonicalProof);

            var signature = signer.sign(kms, kmsKeyResource, hash);

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
