package com.apicatalog.cel.resolver;

import com.apicatalog.cel.EventLog;

public interface EventLogLoader {

    EventLog load(String id);
    
}
