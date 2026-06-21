package com.apicatalog.di.io;

import java.util.Map;

public interface Model {

    ProofCursor createCursor(Map<String, Object> signed);

}
