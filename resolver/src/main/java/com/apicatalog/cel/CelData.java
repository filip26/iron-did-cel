package com.apicatalog.cel;

import java.time.Duration;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class CelData {

    private String id;

    private Duration heartbeatFrequency;

    private Set<VerificationMethod> assertionMethods;

    public static CelData of(Map<String, Object> document) {

        var data = new CelData();

        try {
            data.id = (String) document.get("id");

            // // Set heartbeatFrequency to the value of didDocument.heartbeatFrequency
            // which
            // // MUST conform to ISO 8601 duration format.
            // heartbeatFrequency = Duration.parse((String) data.get("heartbeatFrequency"));

            if (document.containsKey("heartbeatFrequency")) {
                data.heartbeatFrequency = Duration.parse("P14D");
                // data.heartbeatFrequency =
                // Duration.parse((String)document.get("heartbeatFrequency"));
            }

            var assertion = document.get("assertionMethod");

            if (assertion instanceof Collection list) {

            }

            return data;

        } catch (ClassCastException | DateTimeParseException e) {
            throw new IllegalArgumentException(e);
        }
    }

    // Recreate initial DID document by removing the did:cel identifier occurrence
    // from the DID document
    public static Map<String, Object> remove(String did, Map<String, Object> document) {
        var newDocument = new HashMap<>(document);

        newDocument.remove("id");

        for (var entry : document.entrySet()) {
            switch (entry.getKey()) {
            case "assertionMethod",
                    "authentication",
                    "keyAgreement",
                    "capabilityInvocation",
                    "capabilityDelegation",
                    "recovery",
                    "verificationMethod":

                if (entry.getValue() instanceof Map map) {
                    newDocument.put(entry.getKey(), removeController(did, map));

                } else if (entry.getValue() instanceof Collection list) {
                    var newList = new ArrayList<>(list.size());
                    for (var item : list) {
                        if (item instanceof Map map) {
                            newList.add(removeController(did, map));

                        } else {
                            newList.add(item);
                        }
                    }
                    newDocument.put(entry.getKey(), newList);
                }
                break;

            default:
                continue;
            }
        }

        return newDocument;
    }

    private static Map<String, Object> removeController(String did, Map<String, Object> method) {

        if (did.equals(method.get("controller"))) {
            var newMethod = new HashMap<>(method);
            newMethod.remove("controller");
            return newMethod;
        }
        return method;
    }

    public String id() {
        return id;
    }

    public Set<VerificationMethod> assertionMethod() {
        // TODO Auto-generated method stub
        return null;
    }

    public Duration heartbeatFrequency() {
        return heartbeatFrequency;
    }

    public boolean isValidFor(String did) {

//        if (data.heartbeatFrequency() == null) {
        /// return fireError(ErrorCode.MISSING_HEARTBEAT_PROPERTY,
        /// eventEntryDigest, cache);
//        }
//
//        // If didDocument.id is not did, stop processing this log and continue with the
//        // next logMap entry.
//        if (!did.equals(data.id())) {
//            return fireError(ErrorCode.INVALID_DOCUMENT_ID, eventEntryDigest, cache);
//        }

        return did.equals(id)
                && heartbeatFrequency != null
//                && assertionMethod()
        ;
    }
    
    

}
