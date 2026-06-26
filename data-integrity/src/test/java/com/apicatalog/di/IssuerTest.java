package com.apicatalog.di;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
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
import com.apicatalog.rdf.canon.RdfCanon;
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

        final String keyAlgorithm;
        AsymmetricSigner signer = null;

        switch (privateKeyCodec.name()) {
        case "ed25519-priv":
            keyAlgorithm = "Ed25519";
            signer = BcEd25519Signer.getInstance(privateKeyCodec.decode(privateKey))::sign;
            break;

        default:
            throw new IllegalArgumentException();
        }
        ;

        Proof proof = null;

        var composer = new NativeComposer<Map<String, ? extends Object>>();

        if (DataIntegrityProof.TYPE_NAME.equals(options.get("type"))) {

            var proofDraft = DataIntegrityProof.createDraft(
                    options,
                    cryptosuite -> CryptoSuites.getInstance(cryptosuite, keyAlgorithm));

            var canonicalPayload = switch (proofDraft.c14n()) {
            case "JCS" -> Jcs.canonize(document);
            case "RDFC" -> rdfc(document);
            default -> throw new IllegalStateException(
                    """
                    Unsupported c14n = %s.
                    """.formatted(proofDraft.cryptosuite().c14n()));
            };

            proof = proofDraft.generateProof(
                    signer,
                    proofDraft,
                    new GenericDocument(document, canonicalPayload, proofDraft.c14n()));

            DataIntegrityProof.write((DataIntegrityProof) proof, composer);

        } else if (Ed25519Signature2020.TYPE_NAME.equals(options.get("type"))) {

            assertEquals(Ed25519Signature2020.KEY_ALGORITHM, keyAlgorithm);

            var proofDraft = Ed25519Signature2020.createDraft((Map) options);

            byte[] canonicalPayload = rdfc(document);

            proof = Ed25519Signature2020.generateProof(
                    signer,
                    proofDraft,
                    new GenericDocument(document, canonicalPayload, Ed25519Signature2020.C14N));

            Ed25519Signature2020.write((Ed25519Signature2020) proof, composer);
        }

        var proofMap = composer.compose();
        document.put("proof", proofMap);

        IO.println(proofMap);

        Map<String, Object> expected = Resources.getMap(resource + ".signed.json");

        assertEquals(new String(Jcs.canonize(expected)), new String(Jcs.canonize(document)));
    }

    static final Stream<String> resources() throws IOException {
        return Resources.stream()
                .filter(name -> name.endsWith(".json"))
                .map(name -> name.substring(0, name.indexOf('.')))
                .distinct();
    }

    static final byte[] rdfc(Map<String, ?> document) {

        var canon = RdfCanon.create("SHA-256");

// FIXME       JsonLd.toRdf(document, canon, Options.newOptions());

        final var bos = new ByteArrayOutputStream();

        canon.provide(s -> {
            try {
                bos.write(s.getBytes(StandardCharsets.UTF_8));
                // TODO bos.write('\n'); ???
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        });

        return bos.toByteArray();
    }
}
