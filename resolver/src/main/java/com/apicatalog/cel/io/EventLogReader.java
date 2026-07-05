package com.apicatalog.cel.io;

import java.io.InputStream;

import com.apicatalog.cel.EventLog;

public interface EventLogReader {

    EventLog read(String contentType, InputStream content);

}
