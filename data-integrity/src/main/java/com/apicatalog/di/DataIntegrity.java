package com.apicatalog.di;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.function.BiPredicate;
import java.util.function.Function;

import com.apicatalog.di.io.ModelProcessor;
import com.apicatalog.di.io.ProofAdapter;
import com.apicatalog.di.io.ProofCursor;
import com.apicatalog.trust.document.DigestiblePayload;

public class DataIntegrity {

    
    Map<String, Function<Map<String, Object>, DigestiblePayload>> canonizers;
    
    Collection<String> contexts;
    Map<String, Object> document;
    
    
    
//    @Override
//    public ProofCursor createProofCursor() {
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
////                        c14n[index] = proofResolver.getValue().c14n(documentContexts, map);
////
////                        var c14nDocument = c14nReadyDocuments.get(c14n[index]);
////                        if (c14nDocument == null) {
////                            c14nDocument = new LinkedHashMap<String, Object>(data);
////                            c14nDocument.put(proofProperty, new ArrayList<>());
////                            c14nReadyDocuments.put(c14n[index], c14nDocument);
////                        }
////                        ((Collection) c14nDocument.get(proofProperty)).add(proof);
//                        break;
//                    }
//                }
//            } else {
//                // TODO
//            }
//            index++;
//        }
//
////        return new ProofCursor(data, c14nReadyDocuments);
//      return null;          
//    }




}
