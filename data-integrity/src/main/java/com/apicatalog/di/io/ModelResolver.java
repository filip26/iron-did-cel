package com.apicatalog.di.io;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.function.Predicate;

import com.apicatalog.trust.model.Model;

public class ModelResolver {

    Collection<Entry<Predicate<Collection<String>>, Collection<Model>>> models;

    private ModelResolver(Collection<Entry<Predicate<Collection<String>>, Collection<Model>>> models) {
        this.models = models;
    }

    public static final Builder createBuilder() {
        return new Builder();
    }

    public Collection<String> getContexts(Map<String, Object> document) {
        return switch (document.get("@context")) {
        case Collection<?> col -> col.stream()
                .map(item -> {
                    if (item instanceof String s) {
                        return s;
                    }
                    throw new IllegalArgumentException(
                            "The @context collection contains one or more non-string elements");
                })
                .toList();
        case String context -> List.of(context);
        case null -> null;
        default ->
            throw new IllegalArgumentException("Invalid @context type: expected a string or a collection of strings");
        };
    }

    public Collection<Model> resolve(Collection<String> contexts, Map<String, Object> document) {
        for (var entry : models) {
            if (entry.getKey().test(contexts)) {
                return entry.getValue();
            }
        }
        return List.of();
    }

    public static class Builder {

        Collection<Entry<Predicate<Collection<String>>, Collection<Model>>> models;

        public Builder model(
                Predicate<Collection<String>> selector,
                Model... models) {

            if (this.models == null) {
                this.models = new ArrayList<>();
            }
            this.models.add(Map.entry(selector, Arrays.asList(models)));
            return this;
        }

        public ModelResolver build() {
            return new ModelResolver(models);
        }

//        public Builder proof(CryptoSuite cryptosuite) {
//
//            switch (cryptosuite.c14n()) {
//            case "JCS":
//                proof(new DataIntegrityProof.MapReader(cryptosuite));
//                break;
//            }
//            ;
//
//            return this;
//        }
//
//        public Builder proof(ProofMapReader reader) {
//            if (mapReaders == null) {
//                mapReaders = new ArrayList<ProofMapReader>();
//            }
//            mapReaders.add(reader);
//            return this;
//        }
//
//        public Builder proof(ProofGraphReader reader) {
//            if (graphReaders == null) {
//                graphReaders = new ArrayList<ProofGraphReader>();
//            }
//            graphReaders.add(reader);
//            return this;
//        }

    }

}
