package com.apicatalog.trust.proof;

import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import com.apicatalog.trust.data.DigestiblePayload;
import com.apicatalog.trust.data.GraphData;
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
        this.iterator = proofs.iterator();

        this.currentProof = null;
        this.currentIndex = -1;
        this.currentEntry = null;
    }

    public DigestiblePayload data() {

        if (document == null && data != null) {
            var canonizer = model.newCanonizer();
            var consumer = canonizer.consumer();
            for (var quad : data) {
                if (!"https://w3id.org/security#proof".equals(quad[1])) {
                    consumer.accept(quad[0], quad[1], quad[2], quad[3], quad[4], quad[5], null);
                }
            }

            var canonical = canonizer.canonize();
//            IO.println("DOCUMENT:");
//IO.println(new String(canonical));
            document = new GraphData(data, canonical, model.c14n());
        }
        return document;
    }

    @Override
    public boolean isUnknown() {
        return currentEntry == null || currentEntry.getValue() == null || currentEntry.getKey() == null;
    }

    @Override
    public boolean next() {
        if (!iterator.hasNext()) {
            return false;
        }

        currentEntry = iterator.next();
        currentIndex++;
        currentProof = null;
        return true;
    }

    @Override
    public Proof proof() {
        if (currentProof == null && currentEntry != null && currentEntry.getValue() != null) {

            var reader = currentEntry.getValue();

            var proof = currentEntry.getKey();

            var canonizer = model.newCanonizer();
            var consumer = canonizer.consumer();

            for (var quad : proof) {
                if (!reader.signatureProperty().equals(quad[1])) {
                    consumer.accept(quad[0], quad[1], quad[2], quad[3], quad[4], quad[5], null);
                }
            }

            var canonicalProof = canonizer.canonize();

            currentProof = reader.read(proof, canonicalProof, data());

        }
        return currentProof;
    }
}
