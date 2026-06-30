package com.apicatalog.di.io;

import java.util.Collection;
import java.util.Map;
import java.util.Map.Entry;

import com.apicatalog.trust.document.DigestiblePayload;

public class TypeSpecificProcessor implements ModelProcessor {

    public interface Factory {
        TypeSpecificProcessor newInstance(
                TypeSpecificModel model,
                Map<String, Object> document,
                Collection<Object> proofs,
                Map<Integer, Entry<Map<String, Object>, ProofMapReader>> proofReaders);
    }

    TypeSpecificModel model;
    Collection<Object> proofs;
    Map<Integer, Entry<Map<String, Object>, ProofMapReader>> proofReaders;

    public TypeSpecificProcessor(
            TypeSpecificModel model,
            Collection<Object> proofs,
            Map<Integer, Entry<Map<String, Object>, ProofMapReader>> proofReaders) {
        this.model = model;
        this.proofs = proofs;
        this.proofReaders = proofReaders;
    }

    public static TypeSpecificProcessor newInstance(
            TypeSpecificModel model,
            Map<String, Object> document,
            Collection<Object> proofs,
            Map<Integer, Entry<Map<String, Object>, ProofMapReader>> proofReaders) {

        return null;
    }

    public int proofs() {
        return proofs.size();
    }

    public DigestiblePayload document() {
        return null;
    }

    @Override
    public ProofCursor createProofCursor() {
        // TODO Auto-generated method stub
        return null;
    }

}
