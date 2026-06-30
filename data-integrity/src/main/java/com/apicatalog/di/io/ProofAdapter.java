package com.apicatalog.di.io;

import java.util.Map;

public interface ProofAdapter {


    String c14();
    
//    boolean isAccepted(Map<String, Object> proof);

    
    //
//  default void quad(
//          String subject,
//          String predicate,
//          String object,
//          String datatype,
//          String language,
//          String direction,
//          String graph) {
//      throw new UnsupportedOperationException();
//  }

//  default void 

  // JCS, or Map<predicate, String[]{object, datatype, language, direction}> ->
  // each proof is in a separate graph and must be flat map
//  String c14n(Collection<String> contexts, Map<String, Object> proof);
    
    
//    Proof adapt(Map<String, String> map, Function<String, DigestiblePayload> canonicalDocument);


}
