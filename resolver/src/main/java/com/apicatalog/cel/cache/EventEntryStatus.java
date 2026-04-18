package com.apicatalog.cel.cache;

import java.time.Instant;

import com.apicatalog.cel.CelData;

public record EventEntryStatus(
        Instant created,
        CelData data
        //TODO source? verification datetime? witness verification policy name?
) {

}
