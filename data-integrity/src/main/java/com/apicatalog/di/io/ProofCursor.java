package com.apicatalog.di.io;

import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.function.Function;

import com.apicatalog.trust.Proof;
import com.apicatalog.trust.document.CanonicalPayload;

public class ProofCursor implements Iterator<Proof> {

    Map<String, Function<Map<String, Object>, CanonicalPayload>> canonizers;
    ProofAdapter adapter;

    Map<String, Object> data;
    
    Map<String, CanonicalPayload> payloads;
    
    String proofPropery;
    Iterator<?> proofs;

    protected ProofCursor(Map<String, Object> data, String proofProperty, Iterator<?> proofs, ProofAdapter adapter) {
        this.data = data;
        this.proofPropery = proofProperty;
        this.proofs = proofs;
        this.adapter = adapter;
    }

    public static final ProofCursor createCursor(Map<String, Object> document, ProofAdapter adapter) {

        var proofProperty = "proof"; // FIXME

        var data = new LinkedHashMap<>(document);
        var proofs = data.remove(proofProperty);

        return new ProofCursor(
                data,
                proofProperty,
                switch (proofs) {
                case Collection<?> col -> col.iterator();
                case null -> List.of().iterator();
                default -> List.of(proofs).iterator();
                },
                adapter);
    }

    @Override
    public boolean hasNext() {
        return proofs.hasNext();
    }

    @Override
    public Proof next() {

        if (!hasNext()) {
            throw new NoSuchElementException();
        }
        
        var object = proofs.next();

        if (object instanceof Map map) {
            return adapter.adapt(map, this::canonize);
        }

        throw new ClassCastException();
    }
    
    CanonicalPayload canonize(String c14n) {
        if (payloads != null) {
            var payload = payloads.get(c14n);
            if (payload != null) {
                return payload;
            }
        }
        
        if (canonizers == null || canonizers.isEmpty()) {
            throw new IllegalStateException();
        }
        
        var canonizer = canonizers.get(c14n);
        
        if (canonizer == null) {
            throw new IllegalStateException();
        }
        
        var payload = canonizer.apply(data);
        
        payloads.put(c14n, payload);
        
        return payload;
    }

}
