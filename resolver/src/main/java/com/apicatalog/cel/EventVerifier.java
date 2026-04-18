package com.apicatalog.cel;

public interface EventVerifier {

    void verify(Event event, CelData document);

}
