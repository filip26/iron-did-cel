import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import com.apicatalog.jcs.Jcs;
import com.apicatalog.tree.io.jakarta.JakartaAdapter;

import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonValue;
import jakarta.json.JsonValue.ValueType;
import jakarta.json.stream.JsonParser;

class EventLog {

    
    public static final EventLog parser(JsonParser parser) {

        final JsonObject jsonLog;
        final JsonArray jsonEvents;
        final JsonObject jsonEvent;


//        jsonLog = parser.readObject();
//        jsonEvents = jsonLog.getJsonArray("log");
//
//        // witness the last log event - TODO configurable per request
//        jsonEvent = jsonEvents.getJsonObject(jsonEvents.size() - 1);
//
//        
//        
//        // extract existing proofs
//        var existingProofs = jsonEvent.get("proof");

//        // remove proofs
//        var unsignedEvent = existingProofs != null
//                ? JSON.createObjectBuilder(jsonEvent).remove("proof").build()
//                : jsonEvent;
//
//        var c14Event = Jcs.canonize(unsignedEvent, JakartaAdapter.instance());
        return null;
    }

    public byte[] lastEventHash() {
//        c14Event.getBytes(StandardCharsets.UTF_8)
        return null;
    }

    public byte[] withLastEventProofs(List<Map<String, String>> witnessProofs) {
//      log.
//      var witnessedBuilder = JSON.createObjectBuilder(unsignedEvent);
//      var proofs = mergeProofs(existingProofs, witnessProofs);
//
//      var witnessed = witnessedBuilder.add("proof", proofs).build();
//
//      var updatedLog = JSON.createObjectBuilder(jsonLog);
//
//      updatedLog.add("log", JSON.createArrayBuilder(jsonEvents)
//              .remove(jsonEvents.size() - 1)
//              .add(witnessed));

//        .build().toString().getBytes(StandardCharsets.UTF_8);
        return null;
    }

//    private JsonArray mergeProofs(JsonValue existingProofs, List<JsonObject> witnessProofs) {
//
//        var proofs = JSON.createArrayBuilder();
//
//        if (existingProofs != null && ValueType.NULL != existingProofs.getValueType()) {
//            if (existingProofs instanceof JsonArray array) {
//                array.stream().forEach(proofs::add);
//            } else {
//                proofs.add(existingProofs);
//            }
//        }
//
//        for (var proof : witnessProofs) {
//            proofs.add(proof);
//        }
//
//        return proofs.build();
//    }
}
