package com.apicatalog.di.proof;

import com.apicatalog.di.c14n.CanonicalPayload;
import com.apicatalog.di.signature.Signature;
import com.apicatalog.tree.io.TreeGenerator;
import com.apicatalog.tree.io.TreeIOException;

public interface Proof extends CanonicalPayload {

    String type();

    /**
     * Retrieves the cryptographic signature associated with this proof. If a
     * signature is present, the proof is considered signed and its authenticity can
     * be verified against the canonical representation.
     *
     * @return the {@link Signature} object, or {@code null} if the proof is
     *         unsigned
     */
    Signature signature();

    String verificationMethod();

    String purpose();

    void write(TreeGenerator generator) throws TreeIOException;
}
