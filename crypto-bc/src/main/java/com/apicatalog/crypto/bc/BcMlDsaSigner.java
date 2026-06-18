package com.apicatalog.crypto.bc;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public final class BcMlDsaSigner {

//    private final MLDSAPrivateKeyParameters privateKeyParams;
//    private final PrivateKey privateKey;
    private final byte[] privateKey;

    public BcMlDsaSigner(byte[] privateKey) {
        this.privateKey = privateKey;
    }

    public static BcMlDsaSigner getInstance(byte[] privateKey) throws InvalidKeySpecException {
        try {
//            return new BcMlDsaSigner(mlDsa44PrivateKey(privateKey));
            return new BcMlDsaSigner(privateKey);
        } catch (Exception e) {
            throw new InvalidKeySpecException("Invalid ML-DSA-44 private key", e);
        }
    }

    public byte[] sign(final byte[] data) throws SignatureException {
System.out.println(privateKey.length);
//        MLDSAPrivateKeyParameters params = new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_44, privateKey);

//var params = new MLDSAPrivateKeyParameters(
//        MLDSAParameters.ml_dsa_44,
//        slice(privateKey, 0, 32),    // rho
//        slice(privateKey, 32, 32),   // K
//        slice(privateKey, 64, 64),   // tr
//        slice(privateKey, 128, 192), // s1
//        slice(privateKey, 320, 64),  // s2
//        slice(privateKey, 384, 416),  // t0
//        slice(privateKey, 800, 352)  // t1 (Add length based on your specific layout)
//    );
//

MLDSAPrivateKeyParameters params = new MLDSAPrivateKeyParameters(
        MLDSAParameters.ml_dsa_44,
        Arrays.copyOfRange(privateKey, 0, 32),    // rho
        Arrays.copyOfRange(privateKey, 32, 64),   // K
        Arrays.copyOfRange(privateKey, 64, 128),  // tr
        Arrays.copyOfRange(privateKey, 128, 512), // s1
        Arrays.copyOfRange(privateKey, 512, 896), // s2
        Arrays.copyOfRange(privateKey, 896, 2560),// t0
        null // t1 is not required for the private key parameter object construction
    );

System.out.println(java.util.HexFormat.of().formatHex(privateKey));
        try {

            var pk = privateKey;
            
            if (privateKey.length != 2432) {
                // Slice the first 2432 bytes, ignoring trailing data (e.g., public key/headers)
                pk = Arrays.copyOfRange(privateKey, 0, 2432);
            }
            
//            MLDSAPrivateKeyParameters params = new MLDSAPrivateKeyParameters(
//                    MLDSAParameters.ml_dsa_44, 
//                    pk
//                );

                    MLDSASigner signer = new MLDSASigner();

//                    if (random != null) {
//                        signer.init(true, new ParametersWithRandom(privateKeyParams, random));
//                    } else {
                        signer.init(true, params);
//                    }

                    signer.update(data, 0, data.length);
                  
        return signer.generateSignature();
                
              } catch (CryptoException  e) {
              throw new IllegalStateException("Failed to generate ML-DSA-44 signature", e);
          }

        
//        try {
//            Signature signature = Signature.getInstance("ML-DSA-44", new BouncyCastleProvider());
//
//            signature.initSign(privateKey);
//            signature.update(data);
//
//            return signature.sign();
//        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
//            throw new IllegalStateException(e);
//        }
//
//        final MLDSASigner signer = new MLDSASigner();
//
//        signer.init(true, privateKeyParams);
//        signer.update(data, 0, data.length);
//
//        try {
//            return signer.generateSignature();
//        } catch (CryptoException e) {
//            throw new IllegalStateException("Failed to generate ML-DSA-44 signature", e);
//        }
    }
    
    public static byte[] extractRawKey(byte[] encodedKey) throws IOException {
        try (ASN1InputStream stream = new ASN1InputStream(encodedKey)) {
            ASN1Primitive obj = stream.readObject();
            ASN1Sequence sequence;
            
            if (obj instanceof ASN1TaggedObject) {
                sequence = ASN1Sequence.getInstance((ASN1TaggedObject) obj, true);
            } else {
                sequence = ASN1Sequence.getInstance(obj);
            }
            
            return ASN1OctetString.getInstance(sequence.getObjectAt(sequence.size() - 1)).getOctets();
        }
    }
    
    private static byte[] slice(byte[] array, int offset, int length) {
        byte[] slice = new byte[length];
        System.arraycopy(array, offset, slice, 0, length);
        return slice;
    }

    public static PrivateKey mlDsa44PrivateKey(byte[] rawPrivateKey) throws Exception {

        // id-ml-dsa-44 OID from FIPS 204
        ASN1ObjectIdentifier oid =
                new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.17");

        PrivateKeyInfo info =
                new PrivateKeyInfo(
                        new AlgorithmIdentifier(oid),
                        new DEROctetString(rawPrivateKey));

        return KeyFactory.getInstance("ML-DSA-44", new BouncyCastleProvider())
                .generatePrivate(
                        new PKCS8EncodedKeySpec(info.getEncoded()));
    }
    
    public static PrivateKey toPrivateKey(byte[] rawKey) throws Exception {

        MLDSAPrivateKeyParameters params = new MLDSAPrivateKeyParameters(
                MLDSAParameters.ml_dsa_44,
                rawKey);

        byte[] pkcs8 = PrivateKeyInfoFactory
                .createPrivateKeyInfo(params)
                .getEncoded();

        return KeyFactory.getInstance("ML-DSA", new BouncyCastleProvider())
                .generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
    }

    private static MLDSAPrivateKeyParameters getPrivateKeyFromBytes(final byte[] privKey) {
        return new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_44, privKey);
    }
}