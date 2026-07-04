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

    Map<String, Collection<String[]>> graphs;
    Map<String, ProofGraphReader> readers;

    DigestiblePayload payload;
    Iterator<Entry<String, ProofGraphReader>> iterator;

    Proof currentProof;
    int currentIndex;
    Map.Entry<String, ProofGraphReader> currentEntry;

    @FunctionalInterface
    public interface Factory {
        ProofGraphCursor newInstance(
                GraphModel model,
                Map<String, Collection<String[]>> graphs,
                Map<String, ProofGraphReader> readers);
    }

    public ProofGraphCursor(
            GraphModel model,
            Map<String, Collection<String[]>> graphs,
            Map<String, ProofGraphReader> readers) {
        this.model = model;
        this.graphs = graphs;
        this.readers = readers;
        
        this.iterator = readers.entrySet().iterator();
        this.currentProof = null;
        this.currentIndex = -1;
        this.currentEntry = null;
    }

    public DigestiblePayload data() {

        if (payload == null && graphs.containsKey("@default")) {
            
            var data = graphs.get("@default");
            
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
            payload = new GraphData(data, canonical, model.c14n());
        }
        return payload;
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
        if (currentProof == null && currentEntry != null) {

            var reader = currentEntry.getValue();

            var proof = graphs.get(currentEntry.getKey());

            var canonizer = model.newCanonizer();
            var consumer = canonizer.consumer();

            for (var quad : proof) {
                // filter out signature statement to produce c14n unsigned proof
                if (!reader.signatureTerm().equals(quad[1])) {
                    consumer.accept(quad[0], quad[1], quad[2], quad[3], quad[4], quad[5], null);
                }
            }

            var canonicalProof = canonizer.canonize();

            currentProof = reader.read(proof, canonicalProof, data());

        }
        return currentProof;
    }
}
