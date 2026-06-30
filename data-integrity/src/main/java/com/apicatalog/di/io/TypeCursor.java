package com.apicatalog.di.io;

import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.NoSuchElementException;

import com.apicatalog.trust.Proof;
import com.apicatalog.trust.document.DigestiblePayload;
import com.apicatalog.trust.document.GenericDocument;

public class TypeCursor implements ModelProcessor {

    public interface Factory {
        TypeCursor newInstance(
                TypeSpecificModel model,
                Map<String, Object> document,
                Map<Integer, Entry<Map<String, Object>, ProofMapReader>> proofReaders);
    }

    final TypeSpecificModel model;
    final Map<String, Object> data;
    final Map<Integer, Entry<Map<String, Object>, ProofMapReader>> proofs;

    DigestiblePayload document;
    Iterator<Entry<Integer, Entry<Map<String, Object>, ProofMapReader>>> iterator;
    
    Proof currentProof;
    int currentIndex;
    
    public TypeCursor(
            TypeSpecificModel model,
            Map<String, Object> data,
            Map<Integer, Entry<Map<String, Object>, ProofMapReader>> proofs) {
        this.model = model;
        this.data = data;
        this.proofs = proofs;
        this.iterator = proofs.entrySet().iterator();
    }

// TODO ???
//    public int proofs() {
//        return proofs.length;
//    }

    public DigestiblePayload document() {
        
        if (document == null) {
            var canonical = model.canonize(data);
            // TODO add custom document reader
            document = new GenericDocument(data, canonical, model.c14n());
        }
        
        return document;
    }

    public String proofType() {
        return null;
    }
    
    @Override
    public Proof proof() {
        return currentProof;
    }
        
    @Override
    public boolean hasNext() {
        return iterator.hasNext();
    }

    //TODO returns mode? or boolean top stop on false, drop hasNext()? 
    @Override
    public void next() {

        if (!hasNext()) {
            throw new NoSuchElementException();
        }
       
        var proof = iterator.next();
        
        if (proof.getValue().getKey() instanceof Map map) {
            
            var canonicalProof = model.canonize(map);
            currentProof = proof.getValue().getValue().read(null, map, canonicalProof, document());
            currentIndex = proof.getKey();
            return;
        }

        throw new ClassCastException();
    }
    
    @Override
    public ProofCursor createProofCursor() {

        return null;
//        System.out.println(">> X");
//        // TODO Auto-generated method stub
//        return null;
    }

}
