package com.apicatalog.di.suite;

import com.apicatalog.trust.Signature;

public interface CryptoSuite {

    String id();

    String algorithm();

    String c14n();

    String encode(Signature signature);
}
