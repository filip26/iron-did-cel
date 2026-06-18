package com.apicatalog.crypto.jca;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.X509EncodedKeySpec;

class JcaPrivateKeyAdapter {

    /**
     * Loads Ed25519 from 32-byte raw format.
     */
    public static PrivateKey getEd25519(KeyFactory keyFactory, byte[] rawPrivateKey) throws InvalidKeyException {
        try {
            // Construct the spec for Ed25519 using the raw byte array directly
            NamedParameterSpec paramSpec = NamedParameterSpec.ED25519;
            var spec = new EdECPrivateKeySpec(paramSpec, rawPrivateKey);

            return keyFactory.generatePrivate(spec);

        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static PrivateKey getP256(KeyFactory keyFactory, byte[] rawPrivate) throws InvalidKeyException {
        return toECPrivateKey("secp256r1", keyFactory, rawPrivate);
    }

    public static PrivateKey getP384(KeyFactory keyFactory, byte[] rawPrivate) throws InvalidKeyException {
        return toECPrivateKey("secp384r1", keyFactory, rawPrivate);
    }

    private static PrivateKey toECPrivateKey(String curveName, KeyFactory keyFactory, byte[] rawPrivate)
            throws InvalidKeyException {
        try {
            var params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec(curveName));
            ECParameterSpec ecSpec = params.getParameterSpec(ECParameterSpec.class);

            // Raw private key is a big-endian scalar integer
            BigInteger s = new BigInteger(1, rawPrivate);
            ECPrivateKeySpec spec = new ECPrivateKeySpec(s, ecSpec);
            
            return keyFactory.generatePrivate(spec);

        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        } catch (InvalidParameterSpecException | InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }
    
    private static byte[] reverse(byte[] array) {
        for (int i = 0; i < array.length / 2; i++) {
            byte temp = array[i];
            array[i] = array[array.length - 1 - i];
            array[array.length - 1 - i] = temp;
        }
        return array;
    }

    public static PublicKey getMLDSA(KeyFactory keyFactory, byte[] rawPublicKey) throws InvalidKeyException {
        byte[] x509Header;
//        String algorithmName = "ML-DSA";

        switch (rawPublicKey.length) {
        case 1312: // ML-DSA-44
            x509Header = new byte[] {
                    (byte) 0x30, (byte) 0x82, (byte) 0x05, (byte) 0x32,
                    (byte) 0x30, (byte) 0x0B, (byte) 0x06, (byte) 0x09,
                    (byte) 0x60, (byte) 0x86, (byte) 0x48, (byte) 0x01,
                    (byte) 0x65, (byte) 0x03, (byte) 0x04, (byte) 0x03, (byte) 0x11,
                    (byte) 0x03, (byte) 0x82, (byte) 0x05, (byte) 0x21, (byte) 0x00
            };
            break;
        case 1952: // ML-DSA-65
            x509Header = new byte[] {
                    (byte) 0x30, (byte) 0x82, (byte) 0x07, (byte) 0xB2,
                    (byte) 0x30, (byte) 0x0B, (byte) 0x06, (byte) 0x09,
                    (byte) 0x60, (byte) 0x86, (byte) 0x48, (byte) 0x01,
                    (byte) 0x65, (byte) 0x03, (byte) 0x04, (byte) 0x03, (byte) 0x12,
                    (byte) 0x03, (byte) 0x82, (byte) 0x07, (byte) 0xA1, (byte) 0x00
            };
            break;
        case 2592: // ML-DSA-87
            x509Header = new byte[] {
                    (byte) 0x30, (byte) 0x82, (byte) 0x0A, (byte) 0x32,
                    (byte) 0x30, (byte) 0x0B, (byte) 0x06, (byte) 0x09,
                    (byte) 0x60, (byte) 0x86, (byte) 0x48, (byte) 0x01,
                    (byte) 0x65, (byte) 0x03, (byte) 0x04, (byte) 0x03, (byte) 0x13,
                    (byte) 0x03, (byte) 0x82, (byte) 0x0A, (byte) 0x21, (byte) 0x00
            };
            break;
        default:
            throw new IllegalArgumentException("Unsupported raw ML-DSA public key length: " + rawPublicKey.length);
        }

        byte[] x509EncodedKey = new byte[x509Header.length + rawPublicKey.length];
        System.arraycopy(x509Header, 0, x509EncodedKey, 0, x509Header.length);
        System.arraycopy(rawPublicKey, 0, x509EncodedKey, x509Header.length, rawPublicKey.length);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(x509EncodedKey);
//        KeyFactory keyFactory = KeyFactory.getInstance(algorithmName);
        try {
            return keyFactory.generatePublic(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException(e);
        }

//        Signature verifier = Signature.getInstance(algorithmName);
//        verifier.initVerify(publicKey);
//        verifier.update(message);
//
//        return verifier.verify(signature);
    }
}