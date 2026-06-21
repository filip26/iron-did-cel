package com.apicatalog.di.crypto;

import com.apicatalog.di.signature.Signature;

public interface CryptoSuite {

    String id();

    String algorithm();

    String c14n();

    String encode(Signature signature);
}
