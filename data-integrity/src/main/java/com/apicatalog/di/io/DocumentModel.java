package com.apicatalog.di.io;

import java.util.Collection;
import java.util.Map;

public class DocumentModel {

    String contentType;
    Collection<String> contexts;
    
    public String contentType() {
        return contentType;
    }

    public ProofCursor createCursor(Map<String, Object> signed) {
        // TODO Auto-generated method stub
        return null;
    }
    
    /*
     * 
     *  var processor = DocumentProcessor.get(document);
     *  
     *  var contexts = processor.contexts();
     *  
     *  var cursor = processor.createCursor();
     *  
     *  
     * 
     * 
     */
    
}
