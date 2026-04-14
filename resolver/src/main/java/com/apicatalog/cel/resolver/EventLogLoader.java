package com.apicatalog.cel.resolver;

import java.util.concurrent.CompletableFuture;

import com.apicatalog.cel.EventLog;

@FunctionalInterface
public interface EventLogLoader {

    CompletableFuture<EventLog> load(String did, String endpoint);
    
}
