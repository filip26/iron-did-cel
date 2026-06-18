package com.apicatalog.crypto.jca;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

class JcaMlDsaSigner {


    public static PrivateKey getMLDSA(KeyFactory keyFactory, byte[] rawPublicKey) throws InvalidKeyException {
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

        try {
            return keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException(e);
        }

    }
}