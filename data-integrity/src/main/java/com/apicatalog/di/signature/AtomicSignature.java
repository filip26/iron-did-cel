package com.apicatalog.di.signature;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.SignatureException;

import com.apicatalog.crypto.AsymmetricSigner;
import com.apicatalog.crypto.AsymmetricVerifier;
import com.apicatalog.di.c14n.CanonicalPayload;
import com.apicatalog.di.proof.Proof;

public final class AtomicSignature implements Signature {

    private final String algorithm;

    private final byte[] digest;
    private final byte[] data;

    private final Proof proof;
    private final CanonicalPayload document;

    private AtomicSignature(
            String algorithm,
            byte[] digest,
            byte[] data,
            Proof proof,
            CanonicalPayload document) {
        this.algorithm = algorithm;
        this.digest = digest;
        this.data = data;
        this.proof = proof;
        this.document = document;
    }

    public static AtomicSignature generateSignature(
            AsymmetricSigner signer,
            String algorithm,
            MessageDigest messageDigest,
            Proof proof,
            CanonicalPayload document) throws SignatureException {

        var digest = digest(messageDigest, proof.canonicalPayload(), document.canonicalPayload());

        return new AtomicSignature(
                algorithm,
                digest,
                signer.sign(digest),
                proof,
                document);
    }

    /**
     * Verifies the signature against the provided verifier and public key.
     *
     * @param verifier  the cryptographic verifier used for verification
     * @param publicKey the public key bytes used to verify the signature
     * @return <code>true</code> if the signature is valid, <code>false</code>
     *         otherwise
     * @throws InvalidKeyException if the public key is invalid
     * @throws SignatureException  if the signature verification process fails
     */
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
        var result = new byte[proofHash.length + docHash.length];
        System.arraycopy(proofHash, 0, result, 0, proofHash.length);
        System.arraycopy(docHash, 0, result, proofHash.length, docHash.length);
        return result;
    }

    @Override
    public byte[] toByteArray() {
        return data;
    }

    @Override
    public CanonicalPayload document() {
        return document;
    }

    @Override
    public Proof proof() {
        return proof;
    }

    @Override
    public String algorithm() {
        return algorithm;
    }
}
