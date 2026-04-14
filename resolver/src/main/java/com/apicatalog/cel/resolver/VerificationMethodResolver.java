package com.apicatalog.cel.resolver;

import com.apicatalog.cel.VerificationMethod;

public interface VerificationMethodResolver {

    VerificationMethod resolve(String uri, String purpose);
    
}
