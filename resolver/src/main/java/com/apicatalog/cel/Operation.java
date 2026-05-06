package com.apicatalog.cel;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.json.stream.JsonGenerator;
import jakarta.json.stream.JsonParser;

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
    


    public void write(JsonGenerator gen) {
        gen.writeStartObject();
        gen.write("type", type);
        if (data != null) {
            gen.writeKey("data");
            write(data, gen);
        }
        gen.writeEnd();
    }

    public String type() {
        return type;
    }

    public Map<String, Object> data() {
        return data;
    }

    static void write(Object value, JsonGenerator gen) {
        if (value == null) {
            gen.writeNull();
            return;
        }

        if (value instanceof Boolean bool) {
            gen.write(bool);
            return;
        }

        if (value instanceof String string) {
            gen.write(string);
            return;
        }

        if (value instanceof BigDecimal number) {
            gen.write(number);
        }

        if (value instanceof Map<?, ?> map) {
            gen.writeStartObject();
            for (var entry : map.entrySet()) {
                gen.writeKey((String) entry.getKey());
                write(entry.getValue(), gen);
            }
            gen.writeEnd();
            return;
        }

        if (value instanceof Collection<?> array) {
            gen.writeStartArray();
            for (var el : array) {
                write(el, gen);
            }
            gen.writeEnd();
        }
    }


}
