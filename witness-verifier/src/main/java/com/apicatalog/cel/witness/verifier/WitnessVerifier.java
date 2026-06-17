package com.apicatalog.cel.witness.verifier;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.util.Arrays;
import java.util.function.Function;

public final class WitnessVerifier {

    @FunctionalInterface
    public static interface ProofCanonizer {
        byte[] apply(
                String cryptosuite,
                String created,
                String method,
                String nonce);
    }

    public static WitnessVerifier ECDSA_JCS_2019 = new WitnessVerifier(
            "ecdsa-jcs-2019",
            WitnessVerifier::ecAlgos,
            C14nTemplates::jcsDocument,
            C14nTemplates::jcsProof);

    public static WitnessVerifier ECDSA_RDFC_2019 = new WitnessVerifier(
            "ecdsa-rdfc-2019",
            WitnessVerifier::ecAlgos,
            C14nTemplates::rdfcDocument,
            C14nTemplates::rdfcProof);

    public static WitnessVerifier EDDSA_JCS_2022 = new WitnessVerifier(
            "ecdsa-jcs-2019",
            WitnessVerifier::edAlgos,
            C14nTemplates::jcsDocument,
            C14nTemplates::jcsProof);

    public static WitnessVerifier EDDSA_RDFC_2022 = new WitnessVerifier(
            "eddsa-rdfc-2022",
            WitnessVerifier::edAlgos,
            C14nTemplates::rdfcDocument,
            C14nTemplates::rdfcProof);

    private final String suiteName;
    private final Function<PublicKey, String[]> algorithms;

    private final Function<String, byte[]> documentC14n;
    private final ProofCanonizer proofC14n;

    public WitnessVerifier(
            String name,
            Function<PublicKey, String[]> algorithms,
            Function<String, byte[]> documentC14n,
            ProofCanonizer proofC14n) {
        this.suiteName = name;
        this.algorithms = algorithms;
        this.documentC14n = documentC14n;
        this.proofC14n = proofC14n;
    }

    public static WitnessVerifier getInstance(String cryptosuite) {
        return switch (cryptosuite) {
        case "ecdsa-jcs-2019" -> ECDSA_JCS_2019;
        case "eddsa-jcs-2022" -> EDDSA_JCS_2022;
        case "ecdsa-rdfc-2019" -> ECDSA_RDFC_2019;
        case "eddsa-rdfc-2022" -> EDDSA_RDFC_2022;
        case String unknown -> throw new IllegalArgumentException("Unsupported DI cryptosuite [" + unknown + "]");
        };
    }

    public boolean verify(
            PublicKey publicKey,
            byte[] signature,
            String digest,
            String created,
            String method,
            String nonce) {
        var canonicalProof = proofC14n.apply(suiteName, created, method, nonce);
        System.out.println("CNP: " + new String(canonicalProof));
        return verify(publicKey, signature, digest, canonicalProof);
    }

    public boolean verify(PublicKey publicKey, byte[] signature, String digest, byte[] canonicalProof) {
        var canonicalDocument = documentC14n.apply(digest);
        System.out.println("CND: " + new String(canonicalDocument));
        return verify(publicKey, signature, canonicalDocument, canonicalProof);
    }

    public boolean verify(
            PublicKey publicKey,
            byte[] signature,
            byte[] canonicalDocument,
            byte[] canonicalProof) {

        try {
            final var algos = algorithms.apply(publicKey);

            final var hash = hash(algos[0], canonicalDocument, canonicalProof);

            var verifier = Signature.getInstance(algos[1]);

            verifier.initVerify(publicKey);
            verifier.update(hash);
IO.println("SIG " + signature.length);
//return verifier.verify(signature);
            return verifier.verify(toDerSignature(signature));

            
         // Extract R and S components
//            byte[] r = new byte[32];
//            byte[] s = new byte[32];
//            System.arraycopy(signature, 0, r, 0, 32);
//            System.arraycopy(signature, 32, s, 0, 32);
//
//            // Reverse components individually to convert from Little-Endian to Big-Endian
//            reverse(r);
//            reverse(s);
//
//            // Reassemble into the 64-byte P1363 format
//            byte[] fixedSignature = new byte[64];
//            System.arraycopy(r, 0, fixedSignature, 0, 32);
//            System.arraycopy(s, 0, fixedSignature, 32, 32);
//
//            return verifier.verify(fixedSignature);
            
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);

        } catch (InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            throw new IllegalArgumentException(e);
//        } catch (IOException e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//            throw new IllegalStateException(e);
        }
    }

    public String suiteName() {
        return suiteName;
    }

    // For ECDSA (P-256, P-384, etc.)
    private static String[] ecAlgos(PublicKey key) {
        if (key instanceof ECPublicKey ecKey) {
            var bits = ecKey.getParams().getCurve().getField().getFieldSize();
            if (bits <= 256) {
                return new String[] { "SHA-256", "SHA256withECDSA" }; //inP1363Format
            }
            if (bits <= 384) {
                return new String[] { "SHA-384", "SHA384withECDSA" };
            }
            return new String[] { "SHA-512", "SHA512withECDSA" };
        }
        throw new IllegalArgumentException("Unsupported public key [" + key + "]");
    }

    // For Ed25519
    private static String[] edAlgos(PublicKey key) {
        if (key instanceof EdECPublicKey) {
            return new String[] { "SHA-256", "Ed25519" };
        }
        throw new IllegalArgumentException("Unsupported public key [" + key + "]");
    }

    /**
     * Computes H(canonicalProof) || H(canonicalDocument) using the specified digest
     * algorithm.
     *
     * @param algorithm         the hash algorithm (e.g. "SHA-256")
     * @param canonicalDocument the canonicalized document bytes
     * @param canonicalProof    the canonicalized proof bytes
     * @return concatenation of H(canonicalProof) and H(canonicalDocument)
     * @throws NoSuchAlgorithmException if the algorithm is unavailable
     */
    private static byte[] hash(String algorithm,
            byte[] canonicalDocument,
            byte[] canonicalProof)
            throws NoSuchAlgorithmException {

        var md = MessageDigest.getInstance(algorithm);

        md.update(canonicalProof);
        var proofHash = md.digest();

        var md2 = MessageDigest.getInstance(algorithm);

        
        md2.update(canonicalDocument);
        var docHash = md2.digest();

        var result = new byte[proofHash.length + docHash.length];
        System.arraycopy(proofHash, 0, result, 0, proofHash.length);
        System.arraycopy(docHash, 0, result, proofHash.length, docHash.length);
        
        System.out.println("HASH >>> " + result.length);
        
        return result;
    }

    private static byte[] toDerSignature(final byte[] signature) {
        if (signature == null) {
            throw new IllegalArgumentException("'signature' parameter must not be null.");
        }
        if (signature.length != 64 && signature.length != 96) {
            throw new IllegalArgumentException("'signature' must be exactly 64 or 96 bytes long.");
        }

        try {
        
        final byte[] rBytes = Arrays.copyOfRange(signature, 0, signature.length / 2);
        final byte[] sBytes = Arrays.copyOfRange(signature, signature.length / 2, signature.length);

        // Signum 1 ensures the BigInteger is positive
        final BigInteger r = new BigInteger(1, rBytes);
        final BigInteger s = new BigInteger(1, sBytes);

        // Get the minimal byte representation (including leading zero byte if the highest bit is set)
        byte[] rDer = r.toByteArray();
        byte[] sDer = s.toByteArray();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        // Write R component: Identifier octet for INTEGER (0x02) + Length + Content
        baos.write(0x02);
        baos.write(rDer.length);
        baos.write(rDer);
        
        // Write S component: Identifier octet for INTEGER (0x02) + Length + Content
        baos.write(0x02);
        baos.write(sDer.length);
        baos.write(sDer);
        
        byte[] content = baos.toByteArray();
        
        // Write SEQUENCE: Identifier octet for SEQUENCE (0x30) + Total Length + Content
        ByteArrayOutputStream sequence = new ByteArrayOutputStream();
        sequence.write(0x30);
        
        // Encode length of sequence content (handles cases where length > 127 bytes)
        if (content.length <= 127) {
            sequence.write(content.length);
        } else {
            // Multi-byte length encoding (long form)
            if (content.length <= 255) {
                sequence.write(0x81);
                sequence.write(content.length);
            } else {
                sequence.write(0x82);
                sequence.write((content.length >> 8) & 0xFF);
                sequence.write(content.length & 0xFF);
            }
        }
        sequence.write(content);

        return sequence.toByteArray();
        } catch (Exception e) {
            throw new IllegalStateException(e);
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
