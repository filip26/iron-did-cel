package com.apicatalog.cid;

import java.util.Map;

final class ImmutableMultikey implements VerificationMethod {

    private final String id;
    private final String type;
    private final String controller;
    private final String publicKeyMultibase;

    ImmutableMultikey(
            final String id,
            final String type,
            final String controller,
            final String publicKeyMultibase) {
        this.id = id;
        this.type = type;
        this.controller = controller;
        this.publicKeyMultibase = publicKeyMultibase;
    }

    @Override
    public String id() {
        return id;
    }

    @Override
    public String type() {
        return type;
    }

    @Override
    public String controller() {
        return controller;
    }

    @Override
    public String publicKeyMultibase() {
        return publicKeyMultibase;
    }

    @Override
    public Map<String, Object> publicKeyJwk() {
        return null;
    }
}