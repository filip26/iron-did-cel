package com.apicatalog.trust.proof;

import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.NoSuchElementException;

import com.apicatalog.trust.document.DigestiblePayload;
import com.apicatalog.trust.model.GraphModel;

/*
 * 1. JSON-LD expansion + type, uri map
 * 2. separating proof
 * 3. instantiate document function -> out
 * 4. instantiate proof(index) function -> out
 */
public class ProofGraphCursor implements ProofCursor {

    private final GraphModel model;
    private final Collection<String[]> data;
    private final Collection<Map.Entry<Collection<String[]>, ProofGraphReader>> proofs;
    
    DigestiblePayload document;
    Iterator<Entry<Collection<String[]>, ProofGraphReader>> iterator;

    Proof currentProof;
    int currentIndex;
    Map.Entry<Collection<String[]>, ProofGraphReader> currentEntry;

    
    @FunctionalInterface
    public interface Factory {
        ProofGraphCursor newInstance(
                GraphModel model,
                Collection<String[]> data,
                Collection<Map.Entry<Collection<String[]>, ProofGraphReader>> proofs);
    }

    public ProofGraphCursor(
            GraphModel model,
            Collection<String[]> data,
            Collection<Map.Entry<Collection<String[]>, ProofGraphReader>> proofs) {   
        this.model = model;
        this.data = data;
        this.proofs = proofs;
        this.iterator = proofs.iterator();

        this.currentProof = null;
        this.currentIndex = -1;
        this.currentEntry = null;
    }

    public DigestiblePayload document() {
//FIXMe
        if (document == null) {
//            var canonical = model.canonize(data);
//            // TODO add custom document reader
//            document = new GenericDocument(data, canonical, model.c14n());
        }

        return document;
    }

    
    @Override
    public boolean isUnknown() {
        return currentEntry.getValue() != null;
    }

    @Override
    public boolean hasNext() {
        return iterator.hasNext();
    }

    @Override
    public void next() {
        if (!hasNext()) {
            throw new NoSuchElementException();
        }

        currentEntry = iterator.next();
        currentIndex++;
        currentProof = null;
        

//        if (proof.getValue() != null) {
//
//            //TODO filter out signature? too late here
////            var unsignedProof = new HashMap<>(proof.getKey());
////            unsignedProof.remove(proof.getValue().signatureProperty());
////
////            var canonicalProof = model.canonize(unsignedProof);
//
////            currentProof = proof.getValue().read(proof.getKey().getKey(), proof.getKey().getValue(), document());
//        }
    }

    @Override
    public Proof proof() {
        return currentProof;
    }
}
