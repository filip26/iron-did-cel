package com.apicatalog.di.io;

import java.util.Map;
import java.util.function.Function;

import com.apicatalog.trust.Proof;
import com.apicatalog.trust.document.CanonicalPayload;

@FunctionalInterface
public interface ProofAdapter {

    Proof adapt(Map<String, String> map, Function<String, CanonicalPayload> canonicalDocument);
    
}
