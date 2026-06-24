package com.apicatalog.trust.document;

public record GenericPayload(byte[] canonicalPayload, String c14n) implements CanonicalPayload {

}
