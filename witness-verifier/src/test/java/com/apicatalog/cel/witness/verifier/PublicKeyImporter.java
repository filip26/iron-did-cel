package com.apicatalog.cel.witness.verifier;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
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
import java.util.Arrays;

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

    public static PublicKey loadNistCompressed(byte[] compressed, String curveName) {

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
    
    public static  PublicKey getPublicKeyFromBytes(final byte[] pubKey, String curve)  {
        if (pubKey == null || pubKey.length == 0) {
            throw new IllegalArgumentException("Public key bytes must not be null or empty.");
        }
        byte[] uncompressedKey;
        
        // Check if the key is compressed (33 bytes with 0x02 or 0x03 prefix)
        if (pubKey.length == 33 && (pubKey[0] == 0x02 || pubKey[0] == 0x03)) {
            
            // secp256r1 constants
            BigInteger p = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
            BigInteger b = new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
            
            byte[] xBytes = Arrays.copyOfRange(pubKey, 1, 33);
            BigInteger x = new BigInteger(1, xBytes);
            
            // y^2 = (x^3 - 3x + b) mod p
            BigInteger x3 = x.pow(3).mod(p);
            BigInteger threeX = x.multiply(BigInteger.valueOf(3)).mod(p);
            BigInteger ySquare = x3.subtract(threeX).add(b).mod(p);
            
            // Modular square root for p = 3 mod 4: y = (y^2)^((p+1)/4) mod p
            BigInteger exp = p.add(BigInteger.ONE).divide(BigInteger.valueOf(4));
            BigInteger y = ySquare.modPow(exp, p);
            
            // Adjust parity if necessary
            int expectedYBit = pubKey[0] & 1;
            if (y.testBit(0) != (expectedYBit == 1)) {
                y = p.subtract(y);
            }
            
            byte[] xDer = adjustLength(x.toByteArray(), 32);
            byte[] yDer = adjustLength(y.toByteArray(), 32);
            
            uncompressedKey = new byte[65];
            uncompressedKey[0] = 0x04;
            System.arraycopy(xDer, 0, uncompressedKey, 1, 32);
            System.arraycopy(yDer, 0, uncompressedKey, 33, 32);
        } else {
            uncompressedKey = pubKey;
        }

        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec(curve));
            byte[] curveOidDer = params.getEncoded();

            byte[] idEcPublicKeyDer = new byte[] { 0x06, 0x07, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x02, 0x01 };

            ByteArrayOutputStream algIdContent = new ByteArrayOutputStream();
            algIdContent.write(idEcPublicKeyDer);
            algIdContent.write(curveOidDer);
            byte[] algIdBytes = algIdContent.toByteArray();

            ByteArrayOutputStream algIdSeq = new ByteArrayOutputStream();
            algIdSeq.write(0x30);
            writeDerLength(algIdSeq, algIdBytes.length);
            algIdSeq.write(algIdBytes);
            byte[] algId = algIdSeq.toByteArray();

            ByteArrayOutputStream bitStringSeq = new ByteArrayOutputStream();
            bitStringSeq.write(0x03);
            writeDerLength(bitStringSeq, uncompressedKey.length + 1);
            bitStringSeq.write(0x00);
            bitStringSeq.write(uncompressedKey);
            byte[] bitString = bitStringSeq.toByteArray();

            ByteArrayOutputStream x509Seq = new ByteArrayOutputStream();
            x509Seq.write(0x30);
            writeDerLength(x509Seq, algId.length + bitString.length);
            x509Seq.write(algId);
            x509Seq.write(bitString);

            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(x509Seq.toByteArray());
            KeyFactory kf = KeyFactory.getInstance("EC");
            return (ECPublicKey) kf.generatePublic(x509KeySpec);
        } catch (Exception e) {
            e.printStackTrace();
            throw new IllegalStateException("Failed to decode EC public key bytes", e);
        }
    }

    private static byte[] adjustLength(byte[] buffer, int targetLength) {
        if (buffer.length == targetLength) {
            return buffer;
        }
        byte[] adjusted = new byte[targetLength];
        if (buffer.length > targetLength) {
            System.arraycopy(buffer, buffer.length - targetLength, adjusted, 0, targetLength);
        } else {
            System.arraycopy(buffer, 0, adjusted, targetLength - buffer.length, buffer.length);
        }
        return adjusted;
    }
    
    private static void writeDerLength(ByteArrayOutputStream stream, int length) {
        if (length <= 127) {
            stream.write(length);
        } else {
            stream.write(0x81);
            stream.write(length);
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
}