package com.apicatalog.cel.witness.verifier;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import com.apicatalog.multibase.Multibase;
import com.apicatalog.multibase.MultibaseDecoder;
import com.apicatalog.multicodec.codec.KeyCodec;
import com.apicatalog.tree.io.TreeIOException;
import com.apicatalog.tree.io.jakarta.JakartaReader;

import jakarta.json.Json;

class WitnessVerifierTest {

//    @ParameterizedTest
    @MethodSource({ "requests" })
    void testVerify(String name) throws IOException, TreeIOException {
        System.out.println("> " + name);

        var request = resourceAsJson(name + "in.json");
        var proof = resourceAsJson(name + "proof.json");

        System.out.println(request);
        System.out.println(proof);

        var digest = (String) request.get("digestMultibase");

        var cryptosuite = (String) request.get("suite");
        var signature = MultibaseDecoder.getInstance().decode((String) proof.get("proofValue"));
        var created = (String) proof.get("created");
        var method = (String) proof.get("verificationMethod");
        var nonce = (String) proof.get("nonce");

        IO.println(cryptosuite + ", " + signature.length + ", " + digest + ", " + created + ", " + nonce);
        IO.println("< " + method);
        
        var isValid = WitnessVerifier.getInstance(cryptosuite)
                .verify(DidKey.getPublicKey(method), signature, digest, created, method, nonce);

        assertTrue(isValid);
    }

//    @Test
    void testEc256Jcs() {
        var isValid = WitnessVerifier.getInstance("ecdsa-jcs-2019").verify(
                PublicKeyImporter.loadNistCompressed(
                        KeyCodec.P256_PUBLIC_KEY.decode(
                                Multibase.BASE_58_BTC.decode("zDnaer5PFEcdcb2pibj8q6BtPLhUAsF85UAAaf4HzPP4hWzNY")),
                        "secp256r1"
                        ),
                Multibase.BASE_58_BTC.decode(
                        "z381yXZWPi84qKPBQTz8ugg23v5Qd6BQ1qMYfCmU36qH4N8KeCvMzxHWvpQ45n9rrXTSCaKCWQKaGoTXKY9eGBEuvDUVYuani"),
                "z5C5b1uzYJN6pDR3aWgAqUMo",
                "2026-03-01T21:15:16Z",
                "did:key:zDnaer5PFEcdcb2pibj8q6BtPLhUAsF85UAAaf4HzPP4hWzNY#zDnaer5PFEcdcb2pibj8q6BtPLhUAsF85UAAaf4HzPP4hWzNY",
                "1RLi73qEfeGU-O-tC_BGO-zuj2A-ndkrTiU5OK2APAQ");

        assertTrue(isValid);

    }

//    @Test
    void testEd256Rdfc() {
        var isValid = WitnessVerifier.getInstance("eddsa-rdfc-2022").verify(
                PublicKeyImporter.loadEd25519(
                        KeyCodec.ED25519_PUBLIC_KEY.decode(
                                Multibase.BASE_58_BTC.decode("z6MkfFnKw9QwkU32VQYC6TKfAW2A6ueUjfbrFYxq9yQzoowo"))),
                Multibase.BASE_58_BTC.decode(
                        "z3WeFNBVF8uCAgPpYeBm6s6xFuV6xggySZPZCo9CahTH1vrvP5m9wp2f1AtufamCZXU6VRYfKzU1BPsYriZnZKaJV"),
                "z5C5b1uzYJN6pDR3aWgAqUMo",
                "2026-03-02T21:30:36Z",
                "did:key:z6MkfFnKw9QwkU32VQYC6TKfAW2A6ueUjfbrFYxq9yQzoowo#z6MkfFnKw9QwkU32VQYC6TKfAW2A6ueUjfbrFYxq9yQzoowo",
                "QyfGNDSOK0gkTuOEymW6zWlLJqZYjEU7TcagWmeoU1k");

        assertTrue(isValid);
    }

    static final Stream<String> requests() {
        return Stream.of(new File(WitnessVerifierTest.class.getResource("").getPath()).listFiles())
                .filter(File::isFile)
                .map(File::getName)
                .filter(name -> name.endsWith(".in.json"))
                .map(name -> name.substring(0, name.length() - "in.json".length()))
                .sorted();
    }

    @SuppressWarnings("unchecked")
    static Map<Object, ?> resourceAsJson(String name) throws TreeIOException {
        return (Map<Object, ?>) new JakartaReader(Json.createParserFactory(Map.of()))
                .read(WitnessVerifierTest.class.getResourceAsStream(name));
    }

}
