package com.apicatalog.di;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import java.time.Instant;
import java.util.Collection;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import com.apicatalog.crypto.bc.BcEd25519Signer;
import com.apicatalog.di.proof.DataIntegrityProof;
import com.apicatalog.di.proof.Ed25519Signature2020;
import com.apicatalog.di.suite.CryptoSuites;
import com.apicatalog.jcs.Jcs;
import com.apicatalog.multibase.MultibaseDecoder;
import com.apicatalog.multicodec.Multicodec;
import com.apicatalog.multicodec.Multicodec.Tag;
import com.apicatalog.multicodec.MulticodecDecoder;
import com.apicatalog.multicodec.codec.KeyCodec;
import com.apicatalog.security.AsymmetricSigner;
import com.apicatalog.tree.io.java.NativeComposer;
import com.apicatalog.trust.Proof;
import com.apicatalog.trust.document.GenericDocument;

public class IssuerTest {

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

    @ParameterizedTest
    @MethodSource({ "resources" })
    void testIssue(String resource) throws Throwable {

        Map<String, String> keys = Resources.getMap(resource + ".keys.json");
        Map<String, Object> options = Resources.getMap(resource + ".options.json");
        Map<String, Object> document = Resources.getMap(resource + ".unsigned.json");

        var privateKey = MULTIBASE.decode(keys.get("secretKeyMultibase"));
        var privateKeyCodec = MULTICODEC.getCodec(privateKey).orElseThrow();

        String algorithm = null;
        AsymmetricSigner signer = null;

        switch (privateKeyCodec.name()) {
        case "ed25519-priv":
            algorithm = "Ed25519";
            signer = BcEd25519Signer.getInstance(privateKeyCodec.decode(privateKey))::sign;
            break;

        default:
            throw new IllegalArgumentException();
        }
        ;

        Proof proof = null;
        var composer = new NativeComposer<Map<String, ? extends Object>>();

        if (DataIntegrityProof.TYPE.equals(options.get("type"))) {

            var cryptosuite = CryptoSuites.getInstance((String) options.get("cryptosuite"), algorithm);
            assertNotNull(cryptosuite);

            var proofDraft = DataIntegrityProof.createDraft(cryptosuite);

            for (var entry : options.entrySet()) {
                switch (entry.getKey()) {
                case "@context":
                    proofDraft.context((Collection<String>) entry.getValue());
                    break;
                case "created":
                    proofDraft.created(Instant.parse((String) entry.getValue()));
                    break;
                case "expires":
                    proofDraft.expires(Instant.parse((String) entry.getValue()));
                    break;
                case "proofPurpose":
                    proofDraft.purpose((String) entry.getValue());
                    break;
                case "verificationMethod":
                    proofDraft.verificationMethod((String) entry.getValue());
                    break;
                }
            }

            byte[] canonicalPayload = switch (cryptosuite.c14n()) {
            case "JCS" -> Jcs.canonize(document);
            case "RDFC" -> document.toString().getBytes(); // FIXME
            default -> throw new IllegalStateException(
                    """
                    Unsupported c14n = %s.
                    """.formatted(cryptosuite.c14n()));
            };

            proof = cryptosuite.generateProof(
                    signer,
                    proofDraft,
                    new GenericDocument(document, canonicalPayload, cryptosuite.c14n()));

            DataIntegrityProof.write((DataIntegrityProof) proof, composer);

        } else if (Ed25519Signature2020.TYPE.equals(options.get("type"))) {

            assertEquals(Ed25519Signature2020.ALGORITHM, algorithm);

            var proofDraft = Ed25519Signature2020.createDraft((Map) options);

            // FIXME
            byte[] canonicalPayload = document.toString().getBytes();

            proof = Ed25519Signature2020.generateProof(
                    signer,
                    proofDraft,
                    new GenericDocument(document, canonicalPayload, "RDFC"));

            Ed25519Signature2020.write((Ed25519Signature2020) proof, composer);
        }

        assertNotNull(proof);
        assertNotNull(proof.signature());

        var proofMap = composer.compose();
        document.put("proof", proofMap);
        
        IO.println(proofMap);
        return;
    }

    static final Stream<String> resources() throws IOException {
        return Resources.stream()
                .filter(name -> name.endsWith(".json"))
                .map(name -> name.substring(0, name.indexOf('.')))
                .distinct();
    }
}
