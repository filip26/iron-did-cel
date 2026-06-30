package com.apicatalog.di.io;

import java.util.Collection;
import java.util.Map;

import com.apicatalog.trust.Proof;

public interface ProofMapReader {

    boolean isAccepted(Map<String, Object> proof);

    // reads from tree
    Proof read(Collection<String> contexts, Map<String, Object> proof);
    
}
