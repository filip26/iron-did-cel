package com.apicatalog.cel.witness.verifier;

import java.security.PublicKey;

import com.apicatalog.multibase.MultibaseDecoder;
import com.apicatalog.multicodec.codec.KeyCodec;

class DidKey {

    // TODO just helper function for testing purpose only
    static PublicKey getPublicKey(String didKey) {

        var encoded = didKey.substring("did:key:".length(), didKey.length() - "#vm".length());
System.out.println("PK: " + encoded);
        var debased = MultibaseDecoder.getInstance().decode(encoded);

        if (KeyCodec.P256_PUBLIC_KEY.isEncoded(debased)) {
            return PublicKeyImporter.loadNistCompressed(
                    KeyCodec.P256_PUBLIC_KEY.decode(debased),
                    "secp256r1",
                    "SHA256withECDSA");
        }
        
        throw new IllegalArgumentException();

    }

}
