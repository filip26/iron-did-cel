package com.apicatalog.di;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.time.Instant;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import com.apicatalog.crypto.bc.BcEd25519Signer;
import com.apicatalog.di.proof.DataIntegrityProof;
import com.apicatalog.di.proof.Ed25519Signature2020;
import com.apicatalog.di.suite.CryptoSuites;
import com.apicatalog.multibase.MultibaseDecoder;
import com.apicatalog.multicodec.Multicodec;
import com.apicatalog.multicodec.Multicodec.Tag;
import com.apicatalog.multicodec.MulticodecDecoder;
import com.apicatalog.multicodec.codec.KeyCodec;
import com.apicatalog.tree.io.TreeIOException;
import com.apicatalog.trust.AsymmetricSigner;
import com.apicatalog.trust.CanonicalDocument;
import com.apicatalog.trust.Proof;

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
        Map<String, String> options = Resources.getMap(resource + ".options.json");
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
        Map<String, String> proofMap = null;

        if (DataIntegrityProof.TYPE.equals(options.get("type"))) {

            var cryptosuite = CryptoSuites.getInstance(options.get("cryptosuite"), algorithm);
            assertNotNull(cryptosuite);

            var proofDraft = DataIntegrityProof.createDraft(cryptosuite);

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

            byte[] canonicalPayload = switch (cryptosuite.c14n()) {
            case "JCS" -> document.toString().getBytes(); // FIXME
            case "RDFC" -> document.toString().getBytes(); // FIXME
            default -> throw new IllegalStateException();
            };

            proof = cryptosuite.generateProof(
                    signer,
                    proofDraft,
                    new CanonicalDocument(canonicalPayload, cryptosuite.c14n()));

            proofMap = DataIntegrityProof.toMap((DataIntegrityProof)proof);
            
//            var os = new ByteArrayOutputStream();
//            try (JsonGenerator jsonGenerator = JsonFactory.builder().build().createGenerator(os)) {
//                var generator = new Jackson2Generator(jsonGenerator);
//                write((DataIntegrityProof) proof, generator);
//            }
//            IO.println(os.toString());

        } else if (Ed25519Signature2020.TYPE.equals(options.get("type"))) {

            assertEquals(Ed25519Signature2020.ALGORITHM, algorithm);

            var proofDraft = Ed25519Signature2020.createDraft(options);

            // FIXME
            byte[] canonicalPayload = document.toString().getBytes();

            proof = Ed25519Signature2020.generateProof(
                    signer,
                    proofDraft,
                    new CanonicalDocument(canonicalPayload, "RDFC"));

            proofMap = Ed25519Signature2020.toMap((Ed25519Signature2020)proof);
        }

        assertNotNull(proof);
        assertNotNull(proof.signature());
        
        document.put("proof", proofMap);
        IO.println(proofMap);
        return;
    }

    static final Stream<String> resources() throws TreeIOException {
        return Resources.stream()
                .filter(name -> name.endsWith(".json"))
                .map(name -> name.substring(0, name.indexOf('.')))
                .distinct();
    }
}
