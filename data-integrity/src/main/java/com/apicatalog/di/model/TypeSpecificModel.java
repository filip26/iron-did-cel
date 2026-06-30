package com.apicatalog.di.model;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.function.Function;

import com.apicatalog.di.model.TypeCursor.Factory;
import com.apicatalog.di.proof.DataIntegrityProof;
import com.apicatalog.di.suite.CryptoSuite;
import com.apicatalog.trust.model.Model;
import com.apicatalog.trust.model.ModelProcessor;
import com.apicatalog.trust.proof.ProofMapReader;

public class TypeSpecificModel implements Model {

    private final Factory factory;
    private final Collection<ProofMapReader> proofReaders;

    private final String c14n;
    private final Function<Map<String, Object>, byte[]> canonize;

    public TypeSpecificModel(Factory factory, String c14n, Function<Map<String, Object>, byte[]> canonize,
            Collection<ProofMapReader> proofReaders) {
        this.factory = factory;
        this.proofReaders = proofReaders;
        this.c14n = c14n;
        this.canonize = canonize;
    }

    @Override
    public ModelProcessor createCursor(Collection<String> context, Map<String, Object> document) {

        var proofProperty = document.get("proof");

        if (proofProperty == null) {
            return null;
        }

        final Collection<Object> proofs;

        if (!(proofProperty instanceof Collection col)) {
            proofs = List.of(proofProperty);

        } else if (col.isEmpty()) {
            return null;

        } else {
            proofs = col;
        }

        var mapping = new HashMap<Integer, Entry<Map<String, Object>, ProofMapReader>>();

        int index = 0;
        for (var proof : proofs) {

            if (proof instanceof Map proofMap) {

                for (var proofReader : proofReaders) {
                    if (proofReader.isAccepted((Map<String, Object>) proofMap)) {
                        
                        var map = proofMap;
                        
                        if (!map.containsKey("@context")) {
                            map = new HashMap<>(proofMap);
                            map.put("@context", context);
                        }
                        
                        mapping.put(index, Map.entry(map, proofReader));
                        break;
                    }
                }
                index++;
            }
        }

        if (mapping.isEmpty()) {
            return null;
        }

        var data = new LinkedHashMap<>(document);
        data.remove("proof");

        return factory.newInstance(this, data, mapping);
    }

    public static Builder createBuilder(String c14n) {
        return new Builder(c14n);
    }

    public static class Builder {

        final String c14n;

        TypeCursor.Factory factory;

        Function<Map<String, Object>, byte[]> canonize;

        Collection<ProofMapReader> readers;

        private Builder(String c14n) {
            this.c14n = c14n;
        }

        public Builder c14n(Function<Map<String, Object>, byte[]> canonize) {
            this.canonize = canonize;
            return this;
        }

        public Builder processor(TypeCursor.Factory factory) {
            this.factory = factory;
            return this;
        }

        public Builder proof(CryptoSuite cryptosuite) {
            if (!c14n.equals(cryptosuite.c14n())) {
                throw new IllegalArgumentException();
            }
            proof(new DataIntegrityProof.MapReader(cryptosuite));
            return this;
        }

        public Builder proof(ProofMapReader reader) {
            if (readers == null) {
                readers = new ArrayList<ProofMapReader>();
            }
            readers.add(reader);
            return this;
        }

        public Model build() {
            return new TypeSpecificModel(factory, c14n, canonize, readers);
        }
    }

    public byte[] canonize(Map<String, Object> data) {
        return canonize.apply(data);
    }

    public String c14n() {
        return c14n;
    }
}
