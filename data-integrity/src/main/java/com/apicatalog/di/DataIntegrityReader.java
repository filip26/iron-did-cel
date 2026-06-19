package com.apicatalog.di;

import java.util.Collection;
import java.util.Map;

import com.apicatalog.iron.Proof;

public interface DataIntegrityReader {

    Collection<Proof> read(Map<String, Object> document);
    
}
