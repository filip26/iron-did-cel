package com.apicatalog.crypto.bc;

import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.signers.MLDSASigner;

public final class BcMlDsaSigner {

    private final MLDSAPrivateKeyParameters privateKeyParams;

    public BcMlDsaSigner(MLDSAPrivateKeyParameters privateKeyParams) {
        this.privateKeyParams = privateKeyParams;
    }

    public static BcMlDsaSigner getInstance(byte[] privateKey) throws InvalidKeySpecException {
        try {
            return new BcMlDsaSigner(getPrivateKeyFromBytes(privateKey));
        } catch (Exception e) {
            throw new InvalidKeySpecException("Invalid ML-DSA-44 private key", e);
        }
    }

    public byte[] sign(final byte[] data) {

        final MLDSASigner signer = new MLDSASigner();

        signer.init(true, privateKeyParams);

        signer.update(data, 0, data.length);

        try {
            return signer.generateSignature();
        } catch (CryptoException e) {
            throw new IllegalStateException("Failed to generate ML-DSA-44 signature", e);
        }
    }

    private static MLDSAPrivateKeyParameters getPrivateKeyFromBytes(final byte[] privKey) {
        return new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_44, privKey);
    }
}