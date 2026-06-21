package com.apicatalog.di.io;

import java.util.Map;

public class ModelClassifier {

//    Map<String, Object> document;
//
//    ModelResolver(Map<String, Object> document) {
//        this.document = document;
//    }
    
    public static final ModelClassifier createBuilder() {
        return new ModelClassifier();
    }
    
    public Model getModel(Map<String, Object> document) {
        return null;
    }
   
    
}
