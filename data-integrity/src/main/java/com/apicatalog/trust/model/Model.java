package com.apicatalog.trust.model;

import java.util.Collection;
import java.util.Map;

public interface Model {

    ModelProcessor createCursor(Collection<String> context, Map<String, Object> document);
}
