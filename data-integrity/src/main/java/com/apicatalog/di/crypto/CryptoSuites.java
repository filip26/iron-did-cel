package com.apicatalog.di.crypto;

public final class CryptoSuites {

    public static StandardCryptoSuite EDDSA_RDFC_2022 = new StandardCryptoSuite(
            "eddsa-rdfc-2022",
            "Ed25519",
            "RDFC",
            "SHA-256");

    public static StandardCryptoSuite EDDSA_JCS_2022 = new StandardCryptoSuite(
            "eddsa-jcs-2022",
            "Ed25519",
            "JCS",
            "SHA-256");

    public static StandardCryptoSuite ECDSA_RDFC_2019_P256 = new StandardCryptoSuite(
            "ecdsa-rdfc-2019",
            "P-256",
            "RDFC",
            "SHA-256");

    public static StandardCryptoSuite ECDSA_RDFC_2019_P384 = new StandardCryptoSuite(
            "ecdsa-rdfc-2019",
            "P-384",
            "RDFC",
            "SHA-384");

    public static StandardCryptoSuite ECDSA_JCS_2019_P256 = new StandardCryptoSuite(
            "ecdsa-rdfc-2019",
            "P-256",
            "JCS",
            "SHA-256");

    public static StandardCryptoSuite ECDSA_JCS_2019_P384 = new StandardCryptoSuite(
            "ecdsa-rdfc-2019",
            "P-384",
            "JCS",
            "SHA-384");

    public static StandardCryptoSuite getInstance(String id, String algorithm) {

        return switch (id) {
        case "eddsa-rdfc-2022" -> EDDSA_RDFC_2022;
        case "eddsa-jcs-2022" -> EDDSA_JCS_2022;

        case "ecdsa-rdfc-2019" ->
            switch (algorithm) {
            case "P-256" -> ECDSA_RDFC_2019_P256;
            case "P-384" -> ECDSA_RDFC_2019_P384;
            default -> throw new IllegalArgumentException();
            };

        case "ecdsa-jcs-2019" ->
            switch (algorithm) {
            case "P-256" -> ECDSA_JCS_2019_P256;
            case "P-384" -> ECDSA_JCS_2019_P384;
            default -> throw new IllegalArgumentException();
            };

        default -> throw new IllegalArgumentException();
        };
    }
}
