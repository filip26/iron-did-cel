package com.apicatalog.cel.status;

import java.time.Instant;

import com.apicatalog.cel.CelData;

public record EventEntryStatus(
        Instant created,
        Instant verified,
        CelData data
        //TODO source? verification datetime? witness verification policy name?
) {

}
