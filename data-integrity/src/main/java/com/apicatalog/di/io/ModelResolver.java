package com.apicatalog.di.io;

import java.util.Collection;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Predicate;

import com.apicatalog.di.proof.DataIntegrityProof;
import com.apicatalog.trust.Proof;
import com.apicatalog.trust.document.CanonicalPayload;

public class ModelResolver {

    // predicate.accepts(contexts) -> mode, i.e. DataIntegrityModel, Vcdm11Model, Vcdm12Model, ... 
    // TODO !!!!
    Collection<Map.Entry<Predicate<Collection<String>>, DocumentModel>> models;
    
    DocumentModel defaultModel;
    
    // ----
    Map<String, ProofAdapter> proofAdapters = Map.of(
            DataIntegrityProof.TYPE,
            DataIntegrityProof::createProof);

    public static final ModelResolver createBuilder() {
        return new ModelResolver();
    }

    public ProofCursor createCursor(DocumentModel model, Map<String, Object> document) {
        
        
        
        ProofAdapter adapter = null;    //FIXME

        
        return ProofCursor.createCursor(document, adapter);
    }

    public DocumentModel getModel(Map<String, Object> document) {
        return new DocumentModel();
    }
    
    Proof adapt(Map<String, String> map, Function<String, CanonicalPayload> data) {

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
    }

}
