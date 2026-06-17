package com.apicatalog.crypto.jca;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.stream.Collectors;

class PublicKeyImporter {

    /**
     * Loads Ed25519 from 32-byte raw format. Note: Ed25519 raw keys are
     * Little-Endian; Java's EdECPoint expects the standard RFC 8032 representation.
     */
    public static PublicKey loadEd25519(byte[] rawBytes) {
        try {
            // Ed25519 uses the EdDSA algorithm name in Java 15+
            KeyFactory kf = KeyFactory.getInstance("EdDSA");

            // Ed25519 raw keys are essentially the Y-coordinate with a parity bit.
            // We must reverse the array because Java's BigInteger (used internally
            // by some providers) is Big-Endian, while Ed25519 is Little-Endian.
            byte[] reversed = reverse(rawBytes.clone());

            // The EdECPoint takes the BigInteger representation of the encoded point
            BigInteger y = new BigInteger(1, reversed);
            EdECPoint point = new EdECPoint(y.testBit(255), y);

            // Construct the spec for Ed25519
            NamedParameterSpec paramSpec = NamedParameterSpec.ED25519;
            EdECPublicKeySpec spec = new EdECPublicKeySpec(paramSpec, point);

            return kf.generatePublic(spec);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);

        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static PublicKey loadNistCompressed(byte[] compressed, String curveName, String sigAlg) {

        try {
            java.security.AlgorithmParameters params = java.security.AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec(curveName));
            ECParameterSpec ecSpec = params.getParameterSpec(ECParameterSpec.class);

            byte[] xBytes = new byte[compressed.length - 1];
            System.arraycopy(compressed, 1, xBytes, 0, xBytes.length);
            BigInteger x = new BigInteger(1, xBytes);

            BigInteger y = decompressNistY(x, compressed[0], ecSpec.getCurve());

            ECPoint point = new ECPoint(x, y);
            ECPublicKeySpec spec = new ECPublicKeySpec(point, ecSpec);
            return KeyFactory.getInstance("EC").generatePublic(spec);

        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);

        } catch (InvalidParameterSpecException | InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private static BigInteger decompressNistY(BigInteger x, byte prefix, EllipticCurve curve) {
        BigInteger a = curve.getA();
        BigInteger b = curve.getB();
        BigInteger p = ((java.security.spec.ECFieldFp) curve.getField()).getP();

        // y^2 = x^3 + ax + b
        BigInteger rhs = x.multiply(x).multiply(x).add(a.multiply(x)).add(b).mod(p);
        BigInteger y = rhs.modPow(p.add(BigInteger.ONE).shiftRight(2), p);

        if (y.testBit(0) != (prefix == 0x03)) {
            y = p.subtract(y);
        }
        return y;
    }

    private static byte[] reverse(byte[] array) {
        for (int i = 0; i < array.length / 2; i++) {
            byte temp = array[i];
            array[i] = array[array.length - 1 - i];
            array[array.length - 1 - i] = temp;
        }
        return array;
    }
    public static boolean verifyWithRawKey(byte[] rawPublicKey, byte[] message, byte[] signature) throws Exception {
        byte[] x509Header;
        String algorithmName = "ML-DSA";

        switch (rawPublicKey.length) {
            case 1312: // ML-DSA-44
                x509Header = new byte[]{
                    (byte) 0x30, (byte) 0x82, (byte) 0x05, (byte) 0x32, 
                    (byte) 0x30, (byte) 0x0B, (byte) 0x06, (byte) 0x09, 
                    (byte) 0x60, (byte) 0x86, (byte) 0x48, (byte) 0x01, 
                    (byte) 0x65, (byte) 0x03, (byte) 0x04, (byte) 0x03, (byte) 0x11, 
                    (byte) 0x03, (byte) 0x82, (byte) 0x05, (byte) 0x21, (byte) 0x00
                };
                break;
            case 1952: // ML-DSA-65
                x509Header = new byte[]{
                    (byte) 0x30, (byte) 0x82, (byte) 0x07, (byte) 0xB2, 
                    (byte) 0x30, (byte) 0x0B, (byte) 0x06, (byte) 0x09, 
                    (byte) 0x60, (byte) 0x86, (byte) 0x48, (byte) 0x01, 
                    (byte) 0x65, (byte) 0x03, (byte) 0x04, (byte) 0x03, (byte) 0x12, 
                    (byte) 0x03, (byte) 0x82, (byte) 0x07, (byte) 0xA1, (byte) 0x00
                };
                break;
            case 2592: // ML-DSA-87
                x509Header = new byte[]{
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
        KeyFactory keyFactory = KeyFactory.getInstance(algorithmName);
        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        Signature verifier = Signature.getInstance(algorithmName);
        verifier.initVerify(publicKey);
        verifier.update(message);
        
        return verifier.verify(signature);
    }
    
    private static byte[] convertPemToDer(String pem) {
        String base64Data = pem.lines()
                .filter(line -> !line.startsWith("-----BEGIN") && !line.startsWith("-----END"))
                .collect(Collectors.joining());
        return Base64.getDecoder().decode(base64Data.strip());
    }
}