package com.apicatalog.cel.resolver;

import com.apicatalog.cid.VerificationMethod;

public interface VerificationMethodResolver {

    VerificationMethod resolve(String uri, String purpose);
    
}
