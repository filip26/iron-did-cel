package com.apicatalog.di.io;

import java.util.Map;

import com.apicatalog.di.proof.DataIntegrityProof;

public class ModelDetector {

    // Type, c14n??, ProofAdapter
    //TODO
    
    Map<String, ProofAdapter> proofAdapters = Map.of(
            DataIntegrityProof.TYPE,
            DataIntegrityProof::createProof);

    public static final ModelDetector createBuilder() {
        return new ModelDetector();
    }

    public Model getModel(Map<String, Object> document) {
        return new ModelImpl((map, data) -> {

            var type = map.get("type");
            if (type == null) {
                // fallback to JSON-LD processing or fail
                // TODO
                throw new IllegalStateException();
            }

            // detect if it's know type, then detect c14n
            var proofAdapter = proofAdapters.get(type);

            var proof = proofAdapter.adapt(map, data);

            return proof;
        });
    }

}
