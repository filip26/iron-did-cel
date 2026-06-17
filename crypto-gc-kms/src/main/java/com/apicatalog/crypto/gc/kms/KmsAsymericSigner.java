package com.apicatalog.crypto.gc.kms;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import com.apicatalog.crypto.AsymetricSigner;
import com.google.cloud.kms.v1.AsymmetricSignRequest;
import com.google.cloud.kms.v1.Digest;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.PublicKey;
import com.google.protobuf.ByteString;

public class KmsAsymericSigner implements AsymetricSigner {

    @FunctionalInterface
    private interface RequestProvider {
        AsymmetricSignRequest get(KeyManagementServiceClient kms, String resource, byte[] data);
    }

    private final RequestProvider requests;
    private final KeyManagementServiceClient kms;
    private final String kmsKeyResource;

    public KmsAsymericSigner(
            RequestProvider signer,
            KeyManagementServiceClient kms,
            String kmsKeyResource) {
        this.requests = signer;
        this.kms = kms;
        this.kmsKeyResource = kmsKeyResource;
    }

    /**
     * Creates a new {@link KmsAsymericSigner} instance for the specified KMS algorithm
     */
    public static KmsAsymericSigner getInstance(
            PublicKey publicKey,
            KeyManagementServiceClient kms) {

        return switch (publicKey.getAlgorithm()) {
        case EC_SIGN_P256_SHA256 -> new KmsAsymericSigner(
                KmsAsymericSigner::ec256Sign,
                kms,
                publicKey.getName());

        case EC_SIGN_P384_SHA384 -> new KmsAsymericSigner(
                KmsAsymericSigner::ec384Sign,
                kms,
                publicKey.getName());

        case EC_SIGN_ED25519 -> new KmsAsymericSigner(
                KmsAsymericSigner::ed256Sign,
                kms,
                publicKey.getName());

        // PQ experiments
        case PQ_SIGN_SLH_DSA_SHA2_128S -> new KmsAsymericSigner(
                KmsAsymericSigner::dsaSign,
                kms,
                publicKey.getName());

        case PQ_SIGN_ML_DSA_44 -> new KmsAsymericSigner(
                KmsAsymericSigner::dsaSign,
                kms,
                publicKey.getName());

        case PQ_SIGN_ML_DSA_87 -> new KmsAsymericSigner(
                KmsAsymericSigner::dsaSign,
                kms,
                publicKey.getName());

        default ->
            throw new IllegalStateException("Unsupported KMS Key Algorithm [" + publicKey.getAlgorithm() + "]");
        };
    }

    @Override
    public byte[] sign(byte[] data) throws InvalidKeyException, SignatureException {
        return kms.asymmetricSign(requests.get(kms, kmsKeyResource, data)).getSignature().toByteArray();
    }

    private static AsymmetricSignRequest ed256Sign(KeyManagementServiceClient kms, String resource, byte[] blob) {
        final var builder = AsymmetricSignRequest.newBuilder().setName(resource);
        builder.setData(ByteString.copyFrom(blob));
        return builder.build();
    }

    private static AsymmetricSignRequest ec256Sign(KeyManagementServiceClient kms, String resource, byte[] blob) {
        try {
            final var hash = MessageDigest.getInstance("SHA-256").digest(blob);
            final var builder = AsymmetricSignRequest.newBuilder().setName(resource);
            builder.setDigest(Digest.newBuilder().setSha256(ByteString.copyFrom(hash)).build());
            return builder.build();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static AsymmetricSignRequest ec384Sign(KeyManagementServiceClient kms, String resource, byte[] blob) {
        try {
            final var hash = MessageDigest.getInstance("SHA-384").digest(blob);
            final var builder = AsymmetricSignRequest.newBuilder().setName(resource);
            builder.setDigest(Digest.newBuilder().setSha384(ByteString.copyFrom(hash)).build());

            return builder.build();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static AsymmetricSignRequest dsaSign(KeyManagementServiceClient kms, String resource, byte[] blob) {
        final var builder = AsymmetricSignRequest.newBuilder().setName(resource);
        builder.setData(ByteString.copyFrom(blob));
        return builder.build();
    }
}
