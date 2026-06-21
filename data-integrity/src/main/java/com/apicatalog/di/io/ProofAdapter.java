package com.apicatalog.di.io;

import java.util.Map;
import java.util.function.Function;

import com.apicatalog.trust.CanonicalPayload;
import com.apicatalog.trust.Proof;

@FunctionalInterface
public interface ProofAdapter {

    Proof adapt(Map<String, String> map, Function<String, CanonicalPayload> canonicalDocument);
    
}
