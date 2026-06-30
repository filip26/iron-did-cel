package com.apicatalog.di.io;

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.function.Function;

import com.apicatalog.trust.Proof;
import com.apicatalog.trust.document.DigestiblePayload;

public class ProofCursor implements Iterator<String> {

    Function<String, DigestiblePayload> payloads;
//    ProofAdapter adapter;

    Map<String, Object> data;
    
    int index;
    
    String[] modes;
    
    Map<String, List<Map<String, Object>>> proofs;
    
//    Map<String, DigestiblePayload> payloads;

    String proofPropery;

    ProofCursor(Map<String, Object> data, Map<String, List<Map<String, Object>>> proofs) {
        this.data = data;
    }


    public DigestiblePayload document() {
        
//        var payload = payloads.get(modes[index]);
//        
//        if (payload == null) {
//            
//        }
//        
//        return payload;
        return null;
    }
    
    public String proofType() {
        return null;
    }
    
    public Proof proof() {
        return null;
    }
    
    public String mode() {
        return modes[index];
    }
    
    
    @Override
    public boolean hasNext() {
//        return proofs.hasNext();
        return false;
    }

    //TODO returns mode? or boolean top stop on false, drop hasNext()? 
    @Override
    public String next() {

        if (!hasNext()) {
            throw new NoSuchElementException();
        }

//        var object = proofs.next();

//        if (object instanceof Map map) {
//            return adapter.adapt(map, this::canonize);
//        }

        throw new ClassCastException();
    }

    DigestiblePayload canonize(String c14n) {
//        if (payloads != null) {
//            var payload = payloads.get(c14n);
//            if (payload != null) {
//                return payload;
//            }
//        }
//
//        if (canonizers == null || canonizers.isEmpty()) {
//            throw new IllegalStateException();
//        }
//
//        var canonizer = canonizers.get(c14n);
//
//        if (canonizer == null) {
//            throw new IllegalStateException();
//        }
//
//        var payload = canonizer.apply(data);
//
//        payloads.put(c14n, payload);
//
//        return payload;
        return null;
    }

    
//
//    public static final ProofCursor createCursor(Map<String, Object> document, ProofAdapter adapter) {
//
//        final var proofProperty = "proof"; // FIXME
//
//        final var data = new LinkedHashMap<>(document);
//        final var proofsValue = data.remove(proofProperty);
//
//        if (proofsValue == null) {
//            return null;
//        }
//
//        final Collection<?> proofs;
//
//        if (!(proofsValue instanceof Collection<?> col)) {
//            proofs = List.of(proofsValue);
//
//        } else if (!col.isEmpty()) {
//            proofs = col;
//
//        } else {
//            return null;
//        }
//
//        Collection<Entry<BiPredicate<Collection<String>, Map<String, Object>>, ProofAdapter>> proofC14nResolvers = List
//                .of();
//
//        Collection<String> documentContexts = switch (document.get("@context")) {
//        case Collection col -> col;
//        case String context -> List.of(context);
//        case null -> List.of();
//        default -> throw new IllegalArgumentException();
//        };
//
//        // c14, document with proofs
//        Map<String, Map<String, Object>> c14nReadyDocuments = new HashMap<>();
//        var c14n = new String[proofs.size()];
//
//        // scan for c14ns
//        int index = 0;
//        for (var proof : proofs) {
//            if (proof instanceof Map map) {
//                for (var proofResolver : proofC14nResolvers) {
//                    if (proofResolver.getKey().test(documentContexts, map)) {
//                        c14n[index] = proofResolver.getValue().c14n(documentContexts, map);
//
//                        var c14nDocument = c14nReadyDocuments.get(c14n[index]);
//                        if (c14nDocument == null) {
//                            c14nDocument = new LinkedHashMap<String, Object>(data);
//                            c14nDocument.put(proofProperty, new ArrayList<>());
//                            c14nReadyDocuments.put(c14n[index], c14nDocument);
//                        }
//                        ((Collection) c14nDocument.get(proofProperty)).add(proof);
//                        break;
//                    }
//                }
//            } else {
//                // TODO
//            }
//            index++;
//        }
//
//        // compose c14 ready documents
////        for (var proof :proofs) {
////            
////        }
////        for (int i = 0; i < index; i++) {
////            
////        }
//
//        // canonicalize the documents with proofs with the same c14n
//
//        // return cursor reading c14n proofs from each c14n ready document in preserving
//        // order
//
//        // --------------------------------------
//        return new ProofCursor(
//                data,
//                proofProperty,
//                switch (proofsValue) {
//                case Collection<?> col -> col.iterator();
//                case null -> List.of().iterator();
//                default -> List.of(proofsValue).iterator();
//                },
//                adapter);
//    }


}
