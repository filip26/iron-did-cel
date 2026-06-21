package com.apicatalog.di.io;

import java.util.Map;

public class ModelImpl implements Model {

    ProofAdapter adapter;
    
    ModelImpl(ProofAdapter adapter) {
        this.adapter = adapter;
    }
    
    @Override
    public ProofCursor createCursor(Map<String, Object> document) {
        return ProofCursor.createCursor(document, adapter);
    }

}
