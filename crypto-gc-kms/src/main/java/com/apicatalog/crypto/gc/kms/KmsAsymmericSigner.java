package com.apicatalog.crypto.gc.kms;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import com.apicatalog.crypto.AsymmetricSigner;
import com.google.cloud.kms.v1.AsymmetricSignRequest;
import com.google.cloud.kms.v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm;
import com.google.cloud.kms.v1.Digest;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.protobuf.ByteString;

public class KmsAsymmericSigner implements AsymmetricSigner {

    @FunctionalInterface
    private interface RequestProvider {
        AsymmetricSignRequest get(KeyManagementServiceClient kms, String resource, byte[] data);
    }

    private final RequestProvider requests;
    private final KeyManagementServiceClient kms;
    private final String kmsKeyResource;

    public KmsAsymmericSigner(
            RequestProvider signer,
            KeyManagementServiceClient kms,
            String kmsKeyResource) {
        this.requests = signer;
        this.kms = kms;
        this.kmsKeyResource = kmsKeyResource;
    }

    /**
     * Creates a new {@link KmsAsymmericSigner} instance for the specified KMS algorithm
     */
    public static KmsAsymmericSigner getInstance(
            CryptoKeyVersionAlgorithm algorithm,
            String resource,
            KeyManagementServiceClient kms) {

        return switch (algorithm) {
        case EC_SIGN_P256_SHA256 -> new KmsAsymmericSigner(
                KmsAsymmericSigner::ec256Sign,
                kms,
                resource);

        case EC_SIGN_P384_SHA384 -> new KmsAsymmericSigner(
                KmsAsymmericSigner::ec384Sign,
                kms,
                resource);

        case EC_SIGN_ED25519 -> new KmsAsymmericSigner(
                KmsAsymmericSigner::ed256Sign,
                kms,
                resource);

        // PQ experiments
        case PQ_SIGN_SLH_DSA_SHA2_128S -> new KmsAsymmericSigner(
                KmsAsymmericSigner::dsaSign,
                kms,
                resource);

        case PQ_SIGN_ML_DSA_44 -> new KmsAsymmericSigner(
                KmsAsymmericSigner::dsaSign,
                kms,
                resource);

        case PQ_SIGN_ML_DSA_87 -> new KmsAsymmericSigner(
                KmsAsymmericSigner::dsaSign,
                kms,
                resource);

        default ->
            throw new IllegalArgumentException("Unsupported KMS Key Algorithm [" + algorithm + "]");
        };
    }

    @Override
    public byte[] sign(byte[] data) throws SignatureException {
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
