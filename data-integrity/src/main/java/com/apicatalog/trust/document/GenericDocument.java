package com.apicatalog.trust.document;

import java.util.Map;

public record GenericDocument(Map<String, ?> source, byte[] canonicalPayload, String c14n) implements CanonicalPayload {

}
