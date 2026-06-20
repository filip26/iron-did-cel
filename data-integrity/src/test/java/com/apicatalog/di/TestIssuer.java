package com.apicatalog.di;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.time.Instant;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.apicatalog.crypto.AsymmetricSigner;
import com.apicatalog.crypto.bc.BcEd25519Signer;
import com.apicatalog.di.c14n.CanonicalDocument;
import com.apicatalog.di.crypto.CryptoSuites;
import com.apicatalog.di.proof.DataIntegrityProof;
import com.apicatalog.multibase.MultibaseDecoder;
import com.apicatalog.multicodec.Multicodec;
import com.apicatalog.multicodec.Multicodec.Tag;
import com.apicatalog.multicodec.MulticodecDecoder;
import com.apicatalog.multicodec.codec.KeyCodec;

public class TestIssuer {

    static final MultibaseDecoder MULTIBASE = MultibaseDecoder.getInstance();

    static final MulticodecDecoder MULTICODEC = MulticodecDecoder.getInstance(
            KeyCodec.P256_PUBLIC_KEY,
            KeyCodec.P256_PRIVATE_KEY,
            KeyCodec.P384_PUBLIC_KEY,
            KeyCodec.P384_PRIVATE_KEY,
            KeyCodec.ED25519_PUBLIC_KEY,
            KeyCodec.ED25519_PRIVATE_KEY,
            KeyCodec.MLDSA_44_PUBLIC_KEY,
            KeyCodec.MLDSA_44_PRIVATE_KEY,
            Multicodec.of("falcon-512-pub", Tag.Key, 4652));

    @Test
    void testNewSigner(Map<String, String> keys, Map<String, String> options, Map<String, Object> document)
            throws Throwable {

        var privateKey = MULTIBASE.decode(keys.get("secretKeyMultibase"));
        var privateKeyCodec = MULTICODEC.getCodec(privateKey).orElseThrow();

        String algorithm = null;
        AsymmetricSigner signer = null;

        switch (privateKeyCodec.name()) {
//        case KeyCodec.EDED25519_PRIVATE_KEY_CODE -> "Ed25519";
        case "ed25519-priv":
            algorithm = "Ed25519";
            signer = BcEd25519Signer.getInstance(privateKey)::sign;
            break;

        default:
            throw new IllegalArgumentException();
        }
        ;

        var cryptosuite = CryptoSuites.getInstance(options.get("cryptosuite"), algorithm);
        assertNotNull(cryptosuite);

        var proofDraft = DataIntegrityProof.newBuilder(cryptosuite);

        for (var entry : options.entrySet()) {
            switch (entry.getKey()) {
            case "created":
                proofDraft.created(Instant.parse(entry.getValue()));
                break;
            case "expires":
                proofDraft.expires(Instant.parse(entry.getValue()));
                break;
            case "proofPurpose":
                proofDraft.purpose(entry.getValue());
                break;
            case "verificationMethod":
                proofDraft.verificationMethod(entry.getValue());
                break;
            }
        }

        var proof = cryptosuite.generateProof(signer, proofDraft, new CanonicalDocument(null, cryptosuite.c14n()));

        assertNotNull(proof);
        assertNotNull(proof.signature());
    }
}
