package com.apicatalog.crypto.bc;

import java.math.BigInteger;
import java.security.spec.InvalidKeySpecException;
import java.util.function.Supplier;

import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.util.BigIntegers;

public final class BcEcdsaSigner {

    private final String curve;
    private final ECPrivateKeyParameters privateKeyParams; 
    private final Supplier<ExtendedDigest> digestFactory;

    public BcEcdsaSigner(String curve, ECPrivateKeyParameters privateKeyParams, Supplier<ExtendedDigest> digestFactory) {
        this.curve = curve;
        this.privateKeyParams = privateKeyParams;
        this.digestFactory = digestFactory;
    }

    public static BcEcdsaSigner getP256Instance(byte[] privateKey) throws InvalidKeySpecException {
        return new BcEcdsaSigner(
//                "SHA256withECDSA",
                "secp256r1",
                BcEcdsaSigner.getPrivateKeyFromBytes("secp256r1", privateKey),
                BcEcdsaSigner::createSHA256Digest);
    }

    public static BcEcdsaSigner getP384Instance(byte[] privateKey) throws InvalidKeySpecException {
        return new BcEcdsaSigner(
//                "SHA384withECDSA",
                "secp384r1",
                BcEcdsaSigner.getPrivateKeyFromBytes("secp384r1", privateKey),
                BcEcdsaSigner::createSHA384Digest);
    }

//    getPrivateKeyFromBytes(privateKey)

//    protected ExtendedDigest getDigestIstance() {
//        switch (curveType) {
//        case P256:
//            return new SHA256Digest();
//        case P384:
//            return new SHA384Digest();
////        case P512:
////            return new SHA512Digest();
//        }
//        throw new IllegalStateException();
//    }


    private static ExtendedDigest createSHA256Digest() {
        return new SHA256Digest();
    }

    private static ExtendedDigest createSHA384Digest() {
        return new SHA384Digest();
    }

    public byte[] sign(final byte[] data)  {

        try {

            final ExtendedDigest digest = digestFactory.get();

            final byte[] hash = new byte[digest.getByteLength()];
            digest.update(data, 0, data.length);
            digest.doFinal(hash, 0);

            final ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(digestFactory.get()));

            signer.init(true, privateKeyParams);

            final BigInteger[] signature = signer.generateSignature(hash);

            final byte[] r = BigIntegers.asUnsignedByteArray(signature[0]);
            final byte[] s = BigIntegers.asUnsignedByteArray(signature[1]);

            final byte[] sigBytes = new byte[r.length + s.length];

            System.arraycopy(r, 0, sigBytes, 0, r.length);
            System.arraycopy(s, 0, sigBytes, r.length, s.length);

            return sigBytes;

        } catch (Exception e) {
            e.printStackTrace();
//            throw new SigningError(SigningError.Code.Internal, e);
        }
        return null;
    }

    private static ECPrivateKeyParameters getPrivateKeyFromBytes(final String curve, final byte[] privKey) throws InvalidKeySpecException {
        final ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curve);
        final ECDomainParameters ecParams = new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN(), spec.getH());
        return new ECPrivateKeyParameters(new BigInteger(1, privKey), ecParams);
    }
}