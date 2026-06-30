package com.apicatalog.di.signature;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.SignatureException;
import java.util.HexFormat;

import com.apicatalog.security.AsymmetricSigner;
import com.apicatalog.security.AsymmetricVerifier;
import com.apicatalog.trust.AtomicSignature;
import com.apicatalog.trust.Proof;
import com.apicatalog.trust.document.DigestiblePayload;

public final class ProofValue implements AtomicSignature {

    private final String algorithm;

    private final byte[] digest;
    private final byte[] value;

//    private final Proof proof;
//    private final DigestiblePayload document;

    private ProofValue(
            String algorithm,
            byte[] digest,
            byte[] value
//            Proof proof,
//            DigestiblePayload document
    ) {
        this.algorithm = algorithm;
        this.digest = digest;
        this.value = value;
//        this.proof = proof;
//        this.document = document;
    }

    public static ProofValue createSignature(
            String algorithm,
            MessageDigest messageDigest,
            byte[] value,
            byte[] proof,
            byte[] document) {

        var digest = digest(messageDigest, proof, document);

        return new ProofValue(
                algorithm,
                digest,
                value);
    }

    public static ProofValue generateSignature(
            AsymmetricSigner signer,
            String algorithm,
            MessageDigest messageDigest,
            Proof proof,
            DigestiblePayload document) throws SignatureException {

        var digest = digest(messageDigest, proof.canonicalPayload(), document.canonicalPayload());

        return new ProofValue(
                algorithm,
                digest,
                signer.sign(digest)
//                proof,
//                document
        );
    }

    @Override
    public boolean verify(AsymmetricVerifier verifier, byte[] publicKey)
            throws InvalidKeyException, SignatureException {
        return verifier.verify(publicKey, digest, toByteArray());
    }

    /**
     * Computes the cryptographic hash of the canonical proof concatenated with the
     * cryptographic hash of the canonical document.
     * <p>
     * The output is structured as H(canonicalProof) || H(canonicalDocument) and is
     * utilized as signing or verification data.
     * 
     * @param digest
     * @param canonicalProof    the byte array representing the canonicalized proof
     * @param canonicalDocument the byte array representing the canonicalized
     *                          document
     * @return a byte array containing the concatenated hashes in the specified
     *         order
     */
    private static byte[] digest(
            MessageDigest digest,
            byte[] canonicalProof,
            byte[] canonicalDocument) {

        digest.update(canonicalProof);
        var proofHash = digest.digest();

        digest.update(canonicalDocument);
        var docHash = digest.digest();
        System.out.println("Doc Digest: " + HexFormat.of().formatHex(docHash));
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
    private static byte[] digestFromHashes(byte[] proofHash, byte[] docHash) {
        var digest = new byte[proofHash.length + docHash.length];
        System.arraycopy(proofHash, 0, digest, 0, proofHash.length);
        System.arraycopy(docHash, 0, digest, proofHash.length, docHash.length);
        System.out.println("Digest: " + HexFormat.of().formatHex(digest));
        return digest;
    }

    @Override
    public byte[] toByteArray() {
        return value;
    }
//
//    @Override
//    public DigestiblePayload document() {
//        return document;
//    }
//
//    @Override
//    public Proof proof() {
//        return proof;
//    }

    @Override
    public String algorithm() {
        return algorithm;
    }
}
