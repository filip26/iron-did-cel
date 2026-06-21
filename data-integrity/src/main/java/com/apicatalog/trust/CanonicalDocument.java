package com.apicatalog.trust;

public record CanonicalDocument(byte[] canonicalPayload, String c14n) implements CanonicalPayload {

}
