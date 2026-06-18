package com.apicatalog.crypto.jca;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.function.Function;

public class JcaAsymmetricSigner {

//    private String algorithm;
//    private PrivateKey privateKey;
//    private Function<byte[], byte[]> signatureAdapter;
//
//    private JcaAsymmetricSigner(String algorithm, PrivateKey privateKey, Function<byte[], byte[]> signatureAdapter) {
//        this.algorithm = algorithm;
//        this.privateKey = privateKey;
//        this.signatureAdapter = signatureAdapter;
//    }
//
//    public static JcaAsymmetricSigner getInstance(String crypto, byte[] privateKey)
//            throws NoSuchAlgorithmException, InvalidKeyException {
//        return switch (crypto) {
//        case "P-256" -> new JcaAsymmetricSigner(
//                "SHA256withECDSAinP1363Format", //SHA256withECDSAinP1363Format
//                JcaPrivateKeyAdapter.getP256(KeyFactory.getInstance("EC"), privateKey),
//                JcaAsymmetricSigner::decodeECSignature);
//
//        case "P-384" -> new JcaAsymmetricSigner(
//                "SHA384withECDSA",
//                JcaPrivateKeyAdapter.getP384(KeyFactory.getInstance("EC"), privateKey),
//                Function.identity());
//
//        case "Ed25519" -> new JcaAsymmetricSigner(
//                "Ed25519",
//                JcaPrivateKeyAdapter.getEd25519(KeyFactory.getInstance("Ed25519"), privateKey),
//                Function.identity());
//
////        case "ML-DSA-44" -> new JcaAsymmetricSigner(
////                "ML-DSA",
////                JcaPrivateKeyAdapter.getMLDSA(KeyFactory.getInstance("ML-DSA-44"), privateKey),
////                Function.identity());
//
//        default -> throw new NoSuchAlgorithmException("""
//                                                      Crypto %s is not supported.
//                                                      """.formatted(crypto));
//        };
//    }
//
//    public byte[] sign(byte[] data) throws SignatureException {
//
////        var publicKey = keyAdapter.toPrivateKey(keyFactory, rawPublicKey);
////
////        var adaptedSignature = signatureAdapter.apply(signature);
//
//        try {
//            var signer = Signature.getInstance(algorithm);
//            signer.initSign(privateKey);
//            signer.update(data);
//
//            return signatureAdapter.apply(signer.sign());
//
//        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
//            throw new IllegalStateException(e);
//        }
//    }
//    
//    private static byte[] decodeECSignature(byte[] signature) {
//        // Enforce length constraints for P-256 DER signatures (70-72 bytes)
//        if (signature != null && signature.length >= 70 && signature.length <= 72 && (signature[0] & 0xFF) == 0x30) {
//            return derToRawSignature(signature);
//        }
//        return signature;
//    }
//
//    private static byte[] derToRawSignature(byte[] derSignature) {
//        try {
//            int offset = 1;
//
//            int totalLenByte = derSignature[offset++] & 0xFF;
//            if ((totalLenByte & 0x80) != 0) {
//                int numLengthBytes = totalLenByte & 0x7F;
//                offset += numLengthBytes;
//            }
//
//            if ((derSignature[offset++] & 0xFF) != 0x02) {
//                return derSignature;
//            }
//            int rLen = derSignature[offset++] & 0xFF;
//            int rStart = offset;
//            offset += rLen;
//
//            if ((derSignature[offset++] & 0xFF) != 0x02) {
//                return derSignature;
//            }
//            int sLen = derSignature[offset++] & 0xFF;
//            int sStart = offset;
//
//            byte[] rawOutput = new byte[64];
//
//            // Extract and align R component
//            if (rLen > 32) {
//                System.arraycopy(derSignature, rStart + (rLen - 32), rawOutput, 0, 32);
//            } else {
//                System.arraycopy(derSignature, rStart, rawOutput, 32 - rLen, rLen);
//            }
//
//            // Extract and align S component
//            if (sLen > 32) {
//                System.arraycopy(derSignature, sStart + (sLen - 32), rawOutput, 32, 32);
//            } else {
//                System.arraycopy(derSignature, sStart, rawOutput, 64 - sLen, sLen);
//            }
//
//            return rawOutput;
//        } catch (Exception e) {
//            return derSignature;
//        }
//    }
////    private static byte[] encodeECSignature(byte[] signature) {
////        if (isDerEncoded(signature)) {
////            return derToRawSignature(signature);
////        }
////        return signature;
////    }
//
////    private static byte[] derToRawSignature(byte[] derSignature) {
////        // Determine target coordinate length based on DER container size (P-256 vs P-384)
////        int coordinateLength = (derSignature.length <= 72) ? 32 : 48;
////
////        int rLen = derSignature[3] & 0xFF;
////        int rValueIndex = 4;
////
////        int sTagIndex = rValueIndex + rLen;
////        int sLen = derSignature[sTagIndex + 1] & 0xFF;
////        int sValueIndex = sTagIndex + 2;
////
////        byte[] rawOutput = new byte[coordinateLength * 2];
////
////        // Copy R component, stripping any ASN.1 sign-extension bytes or adding padding zeros
////        int rSrcOffset = rValueIndex;
////        int rCopyLen = rLen;
////        if (rCopyLen > coordinateLength) {
////            rSrcOffset += (rCopyLen - coordinateLength);
////            rCopyLen = coordinateLength;
////        }
////        System.arraycopy(derSignature, rSrcOffset, rawOutput, coordinateLength - rCopyLen, rCopyLen);
////
////        // Copy S component, stripping any ASN.1 sign-extension bytes or adding padding zeros
////        int sSrcOffset = sValueIndex;
////        int sCopyLen = sLen;
////        if (sCopyLen > coordinateLength) {
////            sSrcOffset += (sCopyLen - coordinateLength);
////            sCopyLen = coordinateLength;
////        }
////        System.arraycopy(derSignature, sSrcOffset, rawOutput, (coordinateLength * 2) - sCopyLen, sCopyLen);
////
////        return rawOutput;
////    }
//    
//    public static byte[] p256DerToRaw(byte[] derSignature) {
//        return derToRaw(derSignature, 32);
//    }
//
//    /**
//     * Converts a DER-encoded ECDSA signature to raw concatenated bytes (R || S).
//     * * @param derSignature the ASN.1 DER encoded signature
//     * 
//     * @param keySizeInBytes the coordinate length in bytes (e.g., 32 for P-256, 48
//     *                       for P-384)
//     * @return raw signature bytes of length (2 * keySizeInBytes)
//     * @throws SignatureException if the DER structure is invalid
//     */
//    public static byte[] derToRaw(byte[] derSignature, int keySizeInBytes)
//            //throws SignatureException
//    {
//        if (derSignature == null || derSignature.length < 8 || derSignature[0] != 0x30) {
////            throw new SignatureException("Invalid DER signature format");
//        }
//
//        int index = 1;
//        int seqLength = derSignature[index++] & 0xFF;
//        if ((seqLength & 0x80) != 0) {
//            int numLengthBytes = seqLength & 0x7F;
//            index += numLengthBytes;
//        }
//
//        // Parse R
//        if (derSignature[index++] != 0x02) {
////            throw new SignatureException("Invalid DER signature: missing R integer tag");
//        }
//        int rLength = derSignature[index++] & 0xFF;
//        int rOffset = index;
//        index += rLength;
//
//        // Parse S
//        if (derSignature[index++] != 0x02) {
////            throw new SignatureException("Invalid DER signature: missing S integer tag");
//        }
//        int sLength = derSignature[index++] & 0xFF;
//        int sOffset = index;
//
//        byte[] raw = new byte[keySizeInBytes * 2];
//
//        // Copy R into the first half, trimming potential leading sign-padding byte
//        int rSrcOffset = rOffset;
//        int rCopyLen = rLength;
//        if (rCopyLen > keySizeInBytes) {
//            rSrcOffset += (rCopyLen - keySizeInBytes);
//            rCopyLen = keySizeInBytes;
//        }
//        System.arraycopy(derSignature, rSrcOffset, raw, keySizeInBytes - rCopyLen, rCopyLen);
//
//        // Copy S into the second half, trimming potential leading sign-padding byte
//        int sSrcOffset = sOffset;
//        int sCopyLen = sLength;
//        if (sCopyLen > keySizeInBytes) {
//            sSrcOffset += (sCopyLen - keySizeInBytes);
//            sCopyLen = keySizeInBytes;
//        }
//        System.arraycopy(derSignature, sSrcOffset, raw, (keySizeInBytes * 2) - sCopyLen, sCopyLen);
//
//        return raw;
//    }
//
////    private static byte[] decodeECSignature(byte[] signature) {
////        // Determine encoding using structural ASN.1 length validation rather than the
////        // first byte alone
////        if (!isDerEncoded(signature) && (signature.length == 64 || signature.length == 96)) {
////            return rawToDerSignature(signature);
////        }
////        return signature;
////    }
//
////    private static boolean isDerEncoded(byte[] signature) {
////        // Minimum length for a valid DER ECDSA signature is 8 bytes:
////        // 0x30 (1) + total_len (1) + 0x02 (1) + r_len (1) + r_val (1) + 0x02 (1) +
////        // s_len (1) + s_val (1)
////        // Maximum length for standard curves like secp256k1/prime256v1 is 72 bytes.
////        if (signature == null || signature.length < 8 || signature.length > 72) {
////            return false;
////        }
////
////        // Sequence tag verification
////        if ((signature[0] & 0xFF) != 0x30) {
////            return false;
////        }
////
////        // Total length verification (must match array length minus header)
////        if ((signature[1] & 0xFF) != signature.length - 2) {
////            return false;
////        }
////
////        // Target indices for R element
////        int rTagIndex = 2;
////        int rLenIndex = 3;
////        int rValueIndex = 4;
////
////        if ((signature[rTagIndex] & 0xFF) != 0x02) {
////            return false;
////        }
////
////        int rLen = signature[rLenIndex] & 0xFF;
////        if (rLen == 0 || rValueIndex + rLen >= signature.length) {
////            return false;
////        }
////
////        // R value validation: Cannot be negative
////        if ((signature[rValueIndex] & 0x80) != 0) {
////            return false;
////        }
////
////        // R value validation: No redundant leading zeros allowed
////        if (rLen > 1 && signature[rValueIndex] == 0x00 && (signature[rValueIndex + 1] & 0x80) == 0) {
////            return false;
////        }
////
////        // Target indices for S element
////        int sTagIndex = rValueIndex + rLen;
////        int sLenIndex = sTagIndex + 1;
////        int sValueIndex = sTagIndex + 2;
////
////        // Ensure S header bounds match total length exactly
////        if (sValueIndex >= signature.length) {
////            return false;
////        }
////
////        if ((signature[sTagIndex] & 0xFF) != 0x02) {
////            return false;
////        }
////
////        int sLen = signature[sLenIndex] & 0xFF;
////        if (sLen == 0 || sValueIndex + sLen != signature.length) {
////            return false;
////        }
////
////        // S value validation: Cannot be negative
////        if ((signature[sValueIndex] & 0x80) != 0) {
////            return false;
////        }
////
////        // S value validation: No redundant leading zeros allowed
////        if (sLen > 1 && signature[sValueIndex] == 0x00 && (signature[sValueIndex + 1] & 0x80) == 0) {
////            return false;
////        }
////
////        return true;
////    }
//
//    private static byte[] rawToDerSignature(byte[] rawSignature) {
//        if (rawSignature == null || rawSignature.length == 0 || rawSignature.length % 2 != 0) {
//            throw new IllegalArgumentException("Invalid raw signature length");
//        }
//
//        int coordinateLength = rawSignature.length / 2;
//
//        byte[] rBytes = java.util.Arrays.copyOfRange(rawSignature, 0, coordinateLength);
//        byte[] sBytes = java.util.Arrays.copyOfRange(rawSignature, coordinateLength, rawSignature.length);
//
//        java.math.BigInteger r = new java.math.BigInteger(1, rBytes);
//        java.math.BigInteger s = new java.math.BigInteger(1, sBytes);
//
//        byte[] rDer = r.toByteArray();
//        byte[] sDer = s.toByteArray();
//
//        int rLenFieldSize = (rDer.length < 128) ? 1 : 1 + countLengthBytes(rDer.length);
//        int sLenFieldSize = (sDer.length < 128) ? 1 : 1 + countLengthBytes(sDer.length);
//
//        // Total content inside the sequence: Tag(1) + LengthField + Value for both R
//        // and S
//        int contentLength = 1 + rLenFieldSize + rDer.length + 1 + sLenFieldSize + sDer.length;
//
//        int seqLenFieldSize = (contentLength < 128) ? 1 : 1 + countLengthBytes(contentLength);
//        int totalLength = 1 + seqLenFieldSize + contentLength;
//
//        byte[] derOutput = new byte[totalLength];
//        int offset = 0;
//
//        // Write Sequence Tag
//        derOutput[offset++] = 0x30;
//        offset = writeDerLengthToBuffer(derOutput, offset, contentLength);
//
//        // Write R Integer Tag
//        derOutput[offset++] = 0x02;
//        offset = writeDerLengthToBuffer(derOutput, offset, rDer.length);
//        System.arraycopy(rDer, 0, derOutput, offset, rDer.length);
//        offset += rDer.length;
//
//        // Write S Integer Tag
//        derOutput[offset++] = 0x02;
//        offset = writeDerLengthToBuffer(derOutput, offset, sDer.length);
//        System.arraycopy(sDer, 0, derOutput, offset, sDer.length);
//
//        return derOutput;
//    }
//
//    private static int countLengthBytes(int length) {
//        int bytes = 0;
//        while (length > 0) {
//            bytes++;
//            length >>= 8;
//        }
//        return bytes;
//    }
//
//    private static int writeDerLengthToBuffer(byte[] buffer, int offset, int length) {
//        if (length < 128) {
//            buffer[offset++] = (byte) length;
//        } else {
//            int numBytes = countLengthBytes(length);
//            buffer[offset++] = (byte) (0x80 | numBytes);
//            for (int i = numBytes - 1; i >= 0; i--) {
//                buffer[offset++] = (byte) ((length >> (8 * i)) & 0xFF);
//            }
//        }
//        return offset;
//    }
}
