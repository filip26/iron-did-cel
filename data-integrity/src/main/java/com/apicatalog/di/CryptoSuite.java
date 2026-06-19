package com.apicatalog.di;

import java.security.MessageDigest;
import java.util.function.Function;

public class CryptoSuite {

    String id;
    int keyLength;
    String algorithm;   // ECDSA, Ed25519, ML-DSA-44, ...
    String c14n; // JCS, RDFC, ..

    Function<String, MessageDigest> digestFactory;

//    public Map<String, String> sign(Map<String, Object> document, String method) throws SignatureException {
//
//        try {
//            var canonicalDocument = Jcs.canonize(document, JavaAdapter.instance())
//                    .getBytes(StandardCharsets.UTF_8);
//
//            var created = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
//            var nonce = generateNonce(32);
//
//            var canonicalProof = Templates.jcsProof(name, created, method, nonce);
//
//            var hash = hash(digestName, canonicalDocument, canonicalProof);
//
//            var signature = signer.sign(hash);
//
//            return Templates.jsonProof(
//                    name,
//                    created,
//                    method,
//                    nonce,
//                    signatureEncoder.apply(signature));
//
//        } catch (NoSuchAlgorithmException e) {
//            throw new IllegalStateException(e);
//
//        } catch (TreeIOException e) {
//            throw new IllegalArgumentException(e);
//        }
//    }

    /**
     * Computes the cryptographic hash of the canonical proof concatenated with the
     * cryptographic hash of the canonical document.
     * <p>
     * The output is structured as H(canonicalProof) || H(canonicalDocument) and is
     * utilized as signing or verification data.
     *
     * @param canonicalDocument the byte array representing the canonicalized
     *                          document
     * @param canonicalProof    the byte array representing the canonicalized proof
     * @return a byte array containing the concatenated hashes in the specified
     *         order
     */
    public byte[] digest(
            byte[] canonicalDocument,
            byte[] canonicalProof) {

        var digest = digestFactory.apply(algorithm);

        digest.update(canonicalProof);
        var proofHash = digest.digest();

        digest.update(canonicalDocument);
        var docHash = digest.digest();

        return digestFromHashes(proofHash, docHash);
    }

    /**
     * Generates signing or verification data directly from the pre-computed
     * cryptographic digests of the proof and document.
     * <p>
     * The output is structured as H(canonicalProof) || H(canonicalDocument).
     *
     * @param proofHash the cryptographic hash of the canonical proof
     * @param docHash   the cryptographic hash of the canonical document
     * @return the signing or verification data block containing the concatenated
     *         hashes
     * @throws NullPointerException if proofHash or docHash is null
     */
    public byte[] digestFromHashes(byte[] proofHash, byte[] docHash) {
        var result = new byte[proofHash.length + docHash.length];
        System.arraycopy(proofHash, 0, result, 0, proofHash.length);
        System.arraycopy(docHash, 0, result, proofHash.length, docHash.length);
        return result;
    }

    public String id() {
        return id;
    }

    public String algorithm() {
        return algorithm;
    }

    public String c14n() {
        return c14n;
    }
}
