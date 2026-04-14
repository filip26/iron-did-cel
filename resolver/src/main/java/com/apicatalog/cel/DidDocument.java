package com.apicatalog.cel;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class DidDocument {

    private final String id;

    public DidDocument(
            String id) {
        this.id = id;
    }

    public static DidDocument of(Map<String, Object> document) {

        var id = (String) document.get("id");

        var assertion = document.get("assertionMethod");

        if (assertion instanceof Collection list) {

        }

        return new DidDocument(id);
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

    public VerificationMethod assertion() {
        // TODO Auto-generated method stub
        return null;
    }

}
