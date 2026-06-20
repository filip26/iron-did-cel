package com.apicatalog.di.c14n;

public record CanonicalDocument(byte[] canonicalPayload, String c14n) implements CanonicalPayload {

}
