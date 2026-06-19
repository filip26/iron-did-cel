package com.apicatalog.di;

import java.time.Instant;

public interface DataIntegerityProofDraft extends ProofDraft {

    DataIntegerityProofDraft created(Instant created);

    DataIntegerityProofDraft expires(Instant expires);
        
}
