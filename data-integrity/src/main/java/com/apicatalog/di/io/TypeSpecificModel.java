package com.apicatalog.di.io;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Predicate;

import com.apicatalog.di.io.ModelResolver.Builder;
import com.apicatalog.di.io.TypeSpecificProcessor.Factory;
import com.apicatalog.di.proof.DataIntegrityProof;
import com.apicatalog.di.suite.CryptoSuite;

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
    public ModelProcessor createProcessor(Collection<String> context, Map<String, Object> document) {

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
                        mapping.put(index, Map.entry(proofMap, proofReader));
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

        return factory.newInstance(this, data, proofs, mapping);
    }

    public static Builder createBuilder(String c14n) {
        return new Builder(c14n);
    }

    public static class Builder {

        final String c14n;

        TypeSpecificProcessor.Factory factory;

        Function<Map<String, Object>, byte[]> canonize;

        Collection<ProofMapReader> readers;

        private Builder(String c14n) {
            this.c14n = c14n;
        }

        public Builder c14n(Function<Map<String, Object>, byte[]> canonize) {
            this.canonize = canonize;
            return this;
        }

        public Builder processor(TypeSpecificProcessor.Factory factory) {
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

}
