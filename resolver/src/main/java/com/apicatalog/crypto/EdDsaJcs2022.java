package com.apicatalog.crypto;

import java.security.SecureRandom;
import java.util.Base64;

public class EdDsaJcs2022  {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();


    /**
     * Generates a cryptographically secure, URL-safe nonce.
     *
     * <p>
     * The returned value is a Base64 URL-encoded string without padding, making it
     * safe for use in JSON documents, URLs, HTTP headers, and cryptographic proofs
     * without additional escaping.
     * </p>
     *
     * @param bytesLength the number of random bytes to generate
     * @return a URL-safe, unpadded Base64-encoded nonce string
     */
    private static String generateNonce(int bytesLength) {

        final var nonce = new byte[bytesLength];

        SECURE_RANDOM.nextBytes(nonce);

        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(nonce);
    }
}
