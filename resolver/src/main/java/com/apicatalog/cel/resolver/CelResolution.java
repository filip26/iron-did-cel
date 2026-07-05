package com.apicatalog.cel.resolver;

import com.apicatalog.cel.CelData;

public record CelResolution(
        String location,
        CelData document
        ) {

}
