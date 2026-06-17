package com.apicatalog.crypto.jca;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.X509EncodedKeySpec;

import com.apicatalog.crypto.SignatureVerifier;

public final class JcaSignatureVerifier implements SignatureVerifier {

    @FunctionalInterface
    public interface PublicKeyAdapter {
        PublicKey toPublicKey(KeyFactory keyFactory, byte[] rawPublicKey) throws InvalidKeyException;
    }

    private String algorithm;
    private KeyFactory keyFactory;
    private PublicKeyAdapter keyAdapter;

    private JcaSignatureVerifier(String algorithm, KeyFactory keyFactory, PublicKeyAdapter keyAdapter) {
        this.algorithm = algorithm;
        this.keyFactory = keyFactory;
        this.keyAdapter = keyAdapter;
    }

    public static JcaSignatureVerifier getInstance(String algorithm) throws NoSuchAlgorithmException {
        return switch (algorithm) {
        case "P-256" -> new JcaSignatureVerifier(
                "SHA256withECDSA",
                KeyFactory.getInstance("EC"),
                JcaSignatureVerifier::p256ToPublicKey);
        case "P-384" -> new JcaSignatureVerifier(
                "SHA384withECDSA",
                KeyFactory.getInstance("EC"),
                JcaSignatureVerifier::p384ToPublicKey);

        default -> throw new NoSuchAlgorithmException("""
                                                      Algorithm %s is not supported.
                                                      """.formatted(algorithm));
        };
    }

    @Override
    public boolean verify(byte[] rawPublicKey, byte[] data, byte[] signature)
            throws InvalidKeyException, SignatureException {

        var publicKey = keyAdapter.toPublicKey(keyFactory, rawPublicKey);

     // Determine encoding using structural ASN.1 length validation rather than the first byte alone
        if (!isDerEncoded(signature) && (signature.length == 64 || signature.length == 96)) {
            signature = rawToDerSignature(signature);
        }
        
        // Only convert to DER if the signature is raw (64 or 96 bytes) and does not
        // already start with ASN.1 Sequence identifier (0x30)
//        if ((signature.length == 64 || signature.length == 96) && signature[0] != 0x30) {
//            signature = rawToDerSignature(signature);
//        }

        try {
            var verifier = Signature.getInstance(algorithm);
            verifier.initVerify(publicKey);
            verifier.update(data);

            return verifier.verify(signature);

        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

//    private boolean isDerEncoded(byte[] signature) {
//        if (signature.length < 4) {
//            return false;
//        }
//        // Check for ASN.1 Sequence tag and valid short-form length descriptor matching total array length
//        return signature[0] == 0x30 && (signature[1] & 0xFF) == (signature.length - 2) && signature[2] == 0x02;
//    }

    private static boolean isDerEncoded(byte[] signature) {
        // Minimum length for a valid DER ECDSA signature is 8 bytes:
        // 0x30 (1) + total_len (1) + 0x02 (1) + r_len (1) + r_val (1) + 0x02 (1) + s_len (1) + s_val (1)
        // Maximum length for standard curves like secp256k1/prime256v1 is 72 bytes.
        if (signature == null || signature.length < 8 || signature.length > 72) {
            return false;
        }

        // Sequence tag verification
        if ((signature[0] & 0xFF) != 0x30) {
            return false;
        }

        // Total length verification (must match array length minus header)
        if ((signature[1] & 0xFF) != signature.length - 2) {
            return false;
        }

        // Target indices for R element
        int rTagIndex = 2;
        int rLenIndex = 3;
        int rValueIndex = 4;

        if ((signature[rTagIndex] & 0xFF) != 0x02) {
            return false;
        }

        int rLen = signature[rLenIndex] & 0xFF;
        if (rLen == 0 || rValueIndex + rLen >= signature.length) {
            return false;
        }

        // R value validation: Cannot be negative
        if ((signature[rValueIndex] & 0x80) != 0) {
            return false;
        }

        // R value validation: No redundant leading zeros allowed
        if (rLen > 1 && signature[rValueIndex] == 0x00 && (signature[rValueIndex + 1] & 0x80) == 0) {
            return false;
        }

        // Target indices for S element
        int sTagIndex = rValueIndex + rLen;
        int sLenIndex = sTagIndex + 1;
        int sValueIndex = sTagIndex + 2;

        // Ensure S header bounds match total length exactly
        if (sValueIndex >= signature.length) {
            return false;
        }

        if ((signature[sTagIndex] & 0xFF) != 0x02) {
            return false;
        }

        int sLen = signature[sLenIndex] & 0xFF;
        if (sLen == 0 || sValueIndex + sLen != signature.length) {
            return false;
        }

        // S value validation: Cannot be negative
        if ((signature[sValueIndex] & 0x80) != 0) {
            return false;
        }

        // S value validation: No redundant leading zeros allowed
        if (sLen > 1 && signature[sValueIndex] == 0x00 && (signature[sValueIndex + 1] & 0x80) == 0) {
            return false;
        }

        return true;
    }
//    private static boolean isDerEncoded(byte[] signature) {
//
//        if (signature == null || signature.length < 8) {
//            return false;
//        }
//
//        if ((signature[0] & 0xFF) != 0x30) {
//            return false;
//        }
//
//        int offset = 1;
//        int seqLength;
//
//        int firstLenByte = signature[offset++] & 0xFF;
//
//        if ((firstLenByte & 0x80) == 0) {
//            seqLength = firstLenByte;
//        } else {
//
//            int numLenBytes = firstLenByte & 0x7F;
//
//            if (numLenBytes == 0 || numLenBytes > 4) {
//                return false;
//            }
//
//            if (offset + numLenBytes > signature.length) {
//                return false;
//            }
//
//            seqLength = 0;
//
//            for (int i = 0; i < numLenBytes; i++) {
//                seqLength = (seqLength << 8) | (signature[offset++] & 0xFF);
//            }
//        }
//
//        if (offset + seqLength != signature.length) {
//            return false;
//        }
//
//        return (signature[offset] & 0xFF) == 0x02;
//    }
    
//    private byte[] rawToDerSignature(byte[] rawSignature) {
//        int coordinateLength = rawSignature.length / 2;
//        byte[] rBytes = java.util.Arrays.copyOfRange(rawSignature, 0, coordinateLength);
//        byte[] sBytes = java.util.Arrays.copyOfRange(rawSignature, coordinateLength, rawSignature.length);
//
//        java.math.BigInteger r = new java.math.BigInteger(1, rBytes);
//        java.math.BigInteger s = new java.math.BigInteger(1, sBytes);
//
//        byte[] rDer = r.toByteArray();
//        byte[] sDer = s.toByteArray();
//
//        int totalLength = rDer.length + sDer.length + 4;
//        byte[] der = new byte[totalLength + 2];
//
//        der[0] = 0x30;
//        der[1] = (byte) totalLength;
//        
//        der[2] = 0x02;
//        der[3] = (byte) rDer.length;
//        System.arraycopy(rDer, 0, der, 4, rDer.length);
//
//        int sOffset = 4 + rDer.length;
//        der[sOffset] = 0x02;
//        der[sOffset + 1] = (byte) sDer.length;
//        System.arraycopy(sDer, 0, der, sOffset + 2, sDer.length);
//
//        return der;
//    }
    
    private static byte[] rawToDerSignature(byte[] rawSignature) {
        if (rawSignature == null || rawSignature.length == 0 || rawSignature.length % 2 != 0) {
            throw new IllegalArgumentException("Invalid raw signature length");
        }

        int coordinateLength = rawSignature.length / 2;

        byte[] rBytes = java.util.Arrays.copyOfRange(rawSignature, 0, coordinateLength);
        byte[] sBytes = java.util.Arrays.copyOfRange(rawSignature, coordinateLength, rawSignature.length);

        java.math.BigInteger r = new java.math.BigInteger(1, rBytes);
        java.math.BigInteger s = new java.math.BigInteger(1, sBytes);

        byte[] rDer = r.toByteArray();
        byte[] sDer = s.toByteArray();

        int rLenFieldSize = (rDer.length < 128) ? 1 : 1 + countLengthBytes(rDer.length);
        int sLenFieldSize = (sDer.length < 128) ? 1 : 1 + countLengthBytes(sDer.length);

        // Total content inside the sequence: Tag(1) + LengthField + Value for both R and S
        int contentLength = 1 + rLenFieldSize + rDer.length + 1 + sLenFieldSize + sDer.length;

        int seqLenFieldSize = (contentLength < 128) ? 1 : 1 + countLengthBytes(contentLength);
        int totalLength = 1 + seqLenFieldSize + contentLength;

        byte[] derOutput = new byte[totalLength];
        int offset = 0;

        // Write Sequence Tag
        derOutput[offset++] = 0x30;
        offset = writeDerLengthToBuffer(derOutput, offset, contentLength);

        // Write R Integer Tag
        derOutput[offset++] = 0x02;
        offset = writeDerLengthToBuffer(derOutput, offset, rDer.length);
        System.arraycopy(rDer, 0, derOutput, offset, rDer.length);
        offset += rDer.length;

        // Write S Integer Tag
        derOutput[offset++] = 0x02;
        offset = writeDerLengthToBuffer(derOutput, offset, sDer.length);
        System.arraycopy(sDer, 0, derOutput, offset, sDer.length);

        return derOutput;
    }

    private static int countLengthBytes(int length) {
        int bytes = 0;
        while (length > 0) {
            bytes++;
            length >>= 8;
        }
        return bytes;
    }

    private static int writeDerLengthToBuffer(byte[] buffer, int offset, int length) {
        if (length < 128) {
            buffer[offset++] = (byte) length;
        } else {
            int numBytes = countLengthBytes(length);
            buffer[offset++] = (byte) (0x80 | numBytes);
            for (int i = numBytes - 1; i >= 0; i--) {
                buffer[offset++] = (byte) ((length >> (8 * i)) & 0xFF);
            }
        }
        return offset;
    }
    
//    private static byte[] rawToDerSignature(byte[] rawSignature) {
//
//        int coordinateLength = rawSignature.length / 2;
//
//        byte[] rBytes =
//                java.util.Arrays.copyOfRange(rawSignature, 0, coordinateLength);
//
//        byte[] sBytes =
//                java.util.Arrays.copyOfRange(rawSignature,
//                        coordinateLength,
//                        rawSignature.length);
//
//        java.math.BigInteger r = new java.math.BigInteger(1, rBytes);
//        java.math.BigInteger s = new java.math.BigInteger(1, sBytes);
//
//        byte[] rDer = r.toByteArray();
//        byte[] sDer = s.toByteArray();
//
//        int contentLength =
//                2 + rDer.length +
//                2 + sDer.length;
//
//        java.io.ByteArrayOutputStream out =
//                new java.io.ByteArrayOutputStream();
//
//        out.write(0x30);
//
//        writeDerLength(out, contentLength);
//
//        out.write(0x02);
//        writeDerLength(out, rDer.length);
//        out.write(rDer, 0, rDer.length);
//
//        out.write(0x02);
//        writeDerLength(out, sDer.length);
//        out.write(sDer, 0, sDer.length);
//
//        return out.toByteArray();
//    }
//    
//    private static void writeDerLength(
//            java.io.ByteArrayOutputStream out,
//            int length) {
//
//        if (length < 128) {
//            out.write(length);
//            return;
//        }
//
//        int numBytes = 0;
//        int temp = length;
//
//        while (temp > 0) {
//            numBytes++;
//            temp >>= 8;
//        }
//
//        out.write(0x80 | numBytes);
//
//        for (int i = numBytes - 1; i >= 0; i--) {
//            out.write((length >> (8 * i)) & 0xFF);
//        }
//    }

    public static PublicKey p256ToPublicKey(KeyFactory keyFactory, byte[] rawPublicKey)
            throws InvalidKeyException {

        if (rawPublicKey.length == 33) {
            byte sign = rawPublicKey[0];
            if (sign != 0x02 && sign != 0x03) {
                throw new IllegalArgumentException("Invalid compressed key prefix: " + sign);
            }

            byte[] xBytes = java.util.Arrays.copyOfRange(rawPublicKey, 1, 33);
            java.math.BigInteger x = new java.math.BigInteger(1, xBytes);

            java.math.BigInteger p = new java.math.BigInteger(
                    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
            java.math.BigInteger b = new java.math.BigInteger(
                    "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
            java.math.BigInteger a = p.subtract(java.math.BigInteger.valueOf(3));

            // y^2 = x^3 + ax + b (mod p)
            java.math.BigInteger alpha = x.pow(3).add(a.multiply(x)).add(b).mod(p);
            java.math.BigInteger pow = p.add(java.math.BigInteger.ONE).shiftRight(2);
            java.math.BigInteger y = alpha.modPow(pow, p);

            if (y.testBit(0) != (sign == 0x03)) {
                y = p.subtract(y);
            }

            byte[] uncompressed = new byte[65];
            uncompressed[0] = 0x04;
            System.arraycopy(xBytes, 0, uncompressed, 1, 32);

            byte[] yBytes = y.toByteArray();
            int yLen = yBytes.length;
            if (yLen > 32) {
                System.arraycopy(yBytes, yLen - 32, uncompressed, 33, 32);
            } else {
                System.arraycopy(yBytes, 0, uncompressed, 33 + (32 - yLen), yLen);
            }
            rawPublicKey = uncompressed;
        }

        byte[] x509Header;

        switch (rawPublicKey.length) {
        case 65: // Uncompressed P-256 (secp256r1)
            x509Header = new byte[] {
                    (byte) 0x30, (byte) 0x59,
                    (byte) 0x30, (byte) 0x13,
                    (byte) 0x06, (byte) 0x07, (byte) 0x2A, (byte) 0x86, (byte) 0x48, (byte) 0xCE, (byte) 0x3D,
                    (byte) 0x02, (byte) 0x01,
                    (byte) 0x06, (byte) 0x08, (byte) 0x2A, (byte) 0x86, (byte) 0x48, (byte) 0xCE, (byte) 0x3D,
                    (byte) 0x03, (byte) 0x01, (byte) 0x07,
                    (byte) 0x03, (byte) 0x42, (byte) 0x00
            };
            break;
        default:
            throw new IllegalArgumentException("Unsupported raw P-256 public key length: " + rawPublicKey.length);
        }

        byte[] x509EncodedKey = new byte[x509Header.length + rawPublicKey.length];
        System.arraycopy(x509Header, 0, x509EncodedKey, 0, x509Header.length);
        System.arraycopy(rawPublicKey, 0, x509EncodedKey, x509Header.length, rawPublicKey.length);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(x509EncodedKey);
        try {
            return keyFactory.generatePublic(keySpec);
        } catch (java.security.spec.InvalidKeySpecException e) {
            throw new InvalidKeyException(e);
        }
    }

    public static PublicKey p384ToPublicKey(KeyFactory keyFactory, byte[] rawPublicKey)
            throws InvalidKeyException {
        try {
            java.security.AlgorithmParameters params = java.security.AlgorithmParameters.getInstance("EC");
            params.init(new java.security.spec.ECGenParameterSpec("secp384r1"));
            java.security.spec.ECParameterSpec ecParams = params.getParameterSpec(java.security.spec.ECParameterSpec.class);

            java.math.BigInteger x;
            java.math.BigInteger y;

            if (rawPublicKey.length == 49) { // Compressed P-384
                byte sign = rawPublicKey[0];
                if (sign != 0x02 && sign != 0x03) {
                    throw new IllegalArgumentException("Invalid compressed key prefix: " + sign);
                }
//                byte[] xBytes = java.util.Arrays.copyOfRange(rawPublicKey, 1, 49);
//                x = new java.math.BigInteger(1, xBytes);
//
//                java.math.BigInteger p = new java.math.BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", 16);
//                java.math.BigInteger b = new java.math.BigInteger("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF", 16);
//                java.math.BigInteger a = p.subtract(java.math.BigInteger.valueOf(3));
//
//                java.math.BigInteger alpha = x.pow(3).add(a.multiply(x)).add(b).mod(p);
//                java.math.BigInteger pow = p.add(java.math.BigInteger.ONE).shiftRight(2);
//                y = alpha.modPow(pow, p);
//
//                if (y.testBit(0) != (sign == 0x03)) {
//                    y = p.subtract(y);
//                }
                
                byte[] xBytes = java.util.Arrays.copyOfRange(rawPublicKey, 1, 49);
                x = new java.math.BigInteger(1, xBytes);

                java.math.BigInteger p =
                        ((java.security.spec.ECFieldFp) ecParams.getCurve().getField()).getP();

                java.math.BigInteger a = ecParams.getCurve().getA();
                java.math.BigInteger b = ecParams.getCurve().getB();

                java.math.BigInteger alpha =
                        x.modPow(java.math.BigInteger.valueOf(3), p)
                         .add(a.multiply(x))
                         .add(b)
                         .mod(p);

                y = modSqrt(alpha, p);

                if (y == null) {
                    throw new IllegalArgumentException(
                            "Compressed point is not on secp384r1");
                }

                if (y.testBit(0) != (sign == 0x03)) {
                    y = p.subtract(y);
                }
                
            } else if (rawPublicKey.length == 97) { // Uncompressed P-384 with 0x04 prefix
                if (rawPublicKey[0] != 0x04) {
                    throw new IllegalArgumentException("Invalid uncompressed key prefix: " + rawPublicKey[0]);
                }
                byte[] xBytes = java.util.Arrays.copyOfRange(rawPublicKey, 1, 49);
                byte[] yBytes = java.util.Arrays.copyOfRange(rawPublicKey, 49, 97);
                x = new java.math.BigInteger(1, xBytes);
                y = new java.math.BigInteger(1, yBytes);
            } else if (rawPublicKey.length == 96) { // Raw uncompressed P-384 without prefix (X || Y)
                byte[] xBytes = java.util.Arrays.copyOfRange(rawPublicKey, 0, 48);
                byte[] yBytes = java.util.Arrays.copyOfRange(rawPublicKey, 48, 96);
                x = new java.math.BigInteger(1, xBytes);
                y = new java.math.BigInteger(1, yBytes);
            } else {
                throw new IllegalArgumentException("Unsupported raw P-384 public key length: " + rawPublicKey.length);
            }

            java.security.spec.ECPoint w = new java.security.spec.ECPoint(x, y);
            java.security.spec.ECPublicKeySpec keySpec = new java.security.spec.ECPublicKeySpec(w, ecParams);
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            throw new InvalidKeyException(e);
        }
    }
    
    private static java.math.BigInteger modSqrt(
            java.math.BigInteger n,
            java.math.BigInteger p) {

        if (n.signum() == 0) {
            return java.math.BigInteger.ZERO;
        }

        // Legendre symbol check
        if (!n.modPow(
                p.subtract(java.math.BigInteger.ONE).shiftRight(1),
                p).equals(java.math.BigInteger.ONE)) {
            return null;
        }

        java.math.BigInteger q = p.subtract(java.math.BigInteger.ONE);
        int s = 0;

        while (!q.testBit(0)) {
            q = q.shiftRight(1);
            s++;
        }

        // Fast path when p ≡ 3 mod 4
        if (s == 1) {
            return n.modPow(
                    p.add(java.math.BigInteger.ONE).shiftRight(2),
                    p);
        }

        java.math.BigInteger z = java.math.BigInteger.TWO;

        while (z.modPow(
                p.subtract(java.math.BigInteger.ONE).shiftRight(1),
                p).equals(java.math.BigInteger.ONE)) {
            z = z.add(java.math.BigInteger.ONE);
        }

        java.math.BigInteger c = z.modPow(q, p);

        java.math.BigInteger r =
                n.modPow(
                        q.add(java.math.BigInteger.ONE).shiftRight(1),
                        p);

        java.math.BigInteger t = n.modPow(q, p);

        int m = s;

        while (!t.equals(java.math.BigInteger.ONE)) {

            int i;
            java.math.BigInteger t2 = t;

            for (i = 1; i < m; i++) {
                t2 = t2.multiply(t2).mod(p);

                if (t2.equals(java.math.BigInteger.ONE)) {
                    break;
                }
            }

            java.math.BigInteger bFactor =
                    c.modPow(
                            java.math.BigInteger.ONE.shiftLeft(m - i - 1),
                            p);

            r = r.multiply(bFactor).mod(p);

            c = bFactor.multiply(bFactor).mod(p);

            t = t.multiply(c).mod(p);

            m = i;
        }

        return r;
    }
}
