package com.apicatalog.cel;

import java.util.Set;

public interface EventVerifier {

    void verify(Event event, Set<VerificationMethod> verificationMethod);

}
