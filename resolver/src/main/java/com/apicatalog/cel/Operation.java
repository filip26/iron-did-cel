package com.apicatalog.cel;

import java.util.Map;

public class Operation {

    public static final String CREATE_TYPE = "create";
    public static final String UPDATE_TYPE = "update";
    public static final String DEACTIVATE_TYPE = "deactivate";
    public static final String HEARTBEAT_TYPE = "heartbeat";

    private final String type;
    private final Map<String, Object> data;

    public Operation(String type, Map<String, Object> data) {
        this.type = type;
        this.data = data;
    }
    
    public String type() {
        return type;
    }

    public Map<String, Object> data() {
        return data;
    }
}
