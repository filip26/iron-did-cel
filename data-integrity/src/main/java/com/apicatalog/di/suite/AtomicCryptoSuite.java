package com.apicatalog.di.suite;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.HexFormat;

import com.apicatalog.crypto.AsymmetricSigner;
import com.apicatalog.di.proof.DataIntegrityProof;
import com.apicatalog.di.signature.ProofValue;
import com.apicatalog.trust.CanonicalPayload;
import com.apicatalog.trust.Signature;

public class AtomicCryptoSuite implements CryptoSuite {

    String id;
    String algorithm; // P-256, P-384, Ed25519, ML-DSA-44, ...
    String c14n; // JCS, RDFC, ..
    String digestName;

    public AtomicCryptoSuite(
            String id,
            String algorithm,
            String c14n,
            String digestName) {
        this.id = id;
        this.algorithm = algorithm;
        this.c14n = c14n;
        this.digestName = digestName;
    }

    public DataIntegrityProof generateProof(AsymmetricSigner signer, DataIntegrityProof.Draft proofDraft,
            CanonicalPayload canonicalDocument) throws SignatureException {

        try {
            proofDraft.canonize(c14n);

            var unsigned = proofDraft.get();

            var signature = ProofValue.generateSignature(
                    signer,
                    unsigned.cryptosuite().algorithm(),
                    MessageDigest.getInstance(digestName),
                    unsigned,
                    canonicalDocument);

            proofDraft.signature(signature);
            return proofDraft.get();

        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * }
     * 
     * public Signature signDocumentHash(AsymmetricSigner signer, DataIntegrityProof
     * proof, CanonicalDocument canonicalDocument, byte[] documentHash) {
     * 
     */
//  public Map<String, String> sign(Map<String, Object> document, String method) throws SignatureException {
//
//      try {
//          var canonicalDocument = Jcs.canonize(document, JavaAdapter.instance())
//                  .getBytes(StandardCharsets.UTF_8);
//
//          var created = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
//          var nonce = generateNonce(32);
//
//          var canonicalProof = Templates.jcsProof(name, created, method, nonce);
//
//          var hash = hash(digestName, canonicalDocument, canonicalProof);
//
//          var signature = signer.sign(hash);
//
//          return Templates.jsonProof(
//                  name,
//                  created,
//                  method,
//                  nonce,
//                  signatureEncoder.apply(signature));
//
//      } catch (NoSuchAlgorithmException e) {
//          throw new IllegalStateException(e);
//
//      } catch (TreeIOException e) {
//          throw new IllegalArgumentException(e);
//      }
//  }

    @Override
    public String id() {
        return id;
    }

    @Override
    public String algorithm() {
        return algorithm;
    }

    @Override
    public String c14n() {
        return c14n;
    }

    @Override
    public String encode(Signature signature) {
        return HexFormat.of().formatHex(signature.toByteArray());
    }
}
