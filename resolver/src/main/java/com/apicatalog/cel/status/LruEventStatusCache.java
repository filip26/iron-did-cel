package com.apicatalog.cel.status;

import java.util.LinkedHashMap;
import java.util.Map;

public class LruEventStatusCache implements EventStatus {

    private final Map<String, Object> cache;

    public LruEventStatusCache(final int maxCapacity) {
        this.cache = new LinkedHashMap<String, Object>((int) (maxCapacity / 0.75 + 1), 0.75f, true) {

            private static final long serialVersionUID = 4822962879473741809L;

            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Object> eldest) {
                return this.size() > maxCapacity;
            }
        };
    }

    @Override
    public void set(String eventEntryDigest, Object status) {
        cache.put(eventEntryDigest, status);
    }

    @Override
    public Object get(String eventEntryDigest) {
        return cache.get(eventEntryDigest);
    }

}
