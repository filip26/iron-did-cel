package com.apicatalog.crypto;

import java.util.Map;

public interface CryptoSuite {

    Map<String, ? extends Object> sign(Map<String, Object> map, String string);
    
}
