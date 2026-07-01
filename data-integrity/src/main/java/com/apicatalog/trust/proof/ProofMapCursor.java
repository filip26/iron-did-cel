package com.apicatalog.trust.proof;

import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.NoSuchElementException;

import com.apicatalog.trust.Proof;
import com.apicatalog.trust.document.DigestiblePayload;
import com.apicatalog.trust.document.GenericDocument;
import com.apicatalog.trust.model.TypeSpecificModel;

public class ProofMapCursor implements ProofCursor {

    public interface Factory {
        ProofMapCursor newInstance(
                TypeSpecificModel model,
                Map<String, Object> document,
                Collection<Entry<Map<String, Object>, ProofMapReader>> proofReaders);
    }

    final TypeSpecificModel model;
    final Map<String, Object> data;
    final Collection<Entry<Map<String, Object>, ProofMapReader>> proofs;

    DigestiblePayload document;
    Iterator<Entry<Map<String, Object>, ProofMapReader>> iterator;

    Proof currentProof;
    int currentIndex;

    public ProofMapCursor(
            TypeSpecificModel model,
            Map<String, Object> data,
            Collection<Entry<Map<String, Object>, ProofMapReader>> proofs) {
        this.model = model;
        this.data = data;
        this.proofs = proofs;
        this.iterator = proofs.iterator();

        this.currentIndex = -1;
        this.currentProof = null;
    }

    public int proofs() {
        return proofs.size();
    }

    public DigestiblePayload document() {

        if (document == null) {
            var canonical = model.canonize(data);
            // TODO add custom document reader
            document = new GenericDocument(data, canonical, model.c14n());
        }

        return document;
    }

    @Override
    public boolean isUnknown() {
        return currentProof == null;
    }

    @Override
    public Proof proof() {
        return currentProof;
    }

    @Override
    public boolean hasNext() {
        return iterator.hasNext();
    }

    // TODO returns mode? or boolean top stop on false, drop hasNext()?
    @Override
    public void next() {

        if (!hasNext()) {
            throw new NoSuchElementException();
        }

        var proof = iterator.next();
        currentIndex++;
        currentProof = null;

        if (proof.getValue() != null) {

            var unsignedProof = new HashMap<>(proof.getKey());
            unsignedProof.remove(proof.getValue().signatureProperty());

            var canonicalProof = model.canonize(unsignedProof);

            currentProof = proof.getValue().read(null, proof.getKey(), canonicalProof, document());
        }
    }
}
