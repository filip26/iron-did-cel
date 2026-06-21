package com.apicatalog.di;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import com.apicatalog.crypto.AsymmetricSigner;
import com.apicatalog.crypto.bc.BcEd25519Signer;
import com.apicatalog.di.c14n.CanonicalDocument;
import com.apicatalog.di.crypto.CryptoSuites;
import com.apicatalog.di.proof.DataIntegrityProof;
import com.apicatalog.di.proof.Ed25519Signature2020;
import com.apicatalog.di.proof.Proof;
import com.apicatalog.multibase.MultibaseDecoder;
import com.apicatalog.multicodec.Multicodec;
import com.apicatalog.multicodec.Multicodec.Tag;
import com.apicatalog.multicodec.MulticodecDecoder;
import com.apicatalog.multicodec.codec.KeyCodec;
import com.apicatalog.tree.io.TreeIOException;
import com.apicatalog.tree.io.jakcson.Jackson2Reader;
import com.fasterxml.jackson.core.JsonFactory;

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
    void testNewSigner(String resource) throws Throwable {
        
        Map<String, String> keys = getMap(resource + ".keys.json");
        Map<String, String> options = getMap(resource + ".options.json");
        Map<String, Object> document = getMap(resource + ".unsigned.json");
        

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

        if (DataIntegrityProof.SIMPLE_TYPE.equals(options.get("type"))) {

            var cryptosuite = CryptoSuites.getInstance(options.get("cryptosuite"), algorithm);
            assertNotNull(cryptosuite);

            var proofDraft = DataIntegrityProof.newDraft(cryptosuite);

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

            proof = cryptosuite.generateProof(
                    signer,
                    proofDraft,
                    new CanonicalDocument(null, cryptosuite.c14n()));

        } else if ("Ed25519Signature2020".equals(options.get("type"))) {

            assertEquals(Ed25519Signature2020.ALGORITHM, algorithm);
            
            var proofDraft = Ed25519Signature2020.newDraft(options);

            proof = Ed25519Signature2020.generateProof(
                    signer,
                    proofDraft,
                    new CanonicalDocument(null, "RDFC"));

        }

        assertNotNull(proof);
        assertNotNull(proof.signature());
        return;

    }
    
    static final Stream<String> resources() throws TreeIOException {
        return Stream.of(new File(IssuerTest.class.getResource("").getPath()).listFiles())
                .filter(File::isFile)
                .map(File::getName)
                .filter(name -> name.endsWith(".json"))
                .map(name -> name.substring(0, name.indexOf('.')))
                .distinct();
    }

    static String getResource(String name) throws IOException {
        try (var is = new BufferedInputStream(IssuerTest.class.getResourceAsStream(name))) {
            return new BufferedReader(
                    new InputStreamReader(is, StandardCharsets.UTF_8))
                    .lines()
                    .collect(Collectors.joining("\n"));
        }
    }
    
    @SuppressWarnings("unchecked")
    static <T> Map<String, T> getMap(String name) throws TreeIOException, IOException {
        var reader = new Jackson2Reader(new JsonFactory());

        try (var is = new BufferedInputStream(IssuerTest.class.getResourceAsStream(name))) {
            var input = reader.read(is);
            return (Map<String, T>)input;
        }
    }

}
