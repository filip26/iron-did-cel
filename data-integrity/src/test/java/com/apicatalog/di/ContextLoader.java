package com.apicatalog.di;

import java.net.URI;

import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.document.Document;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.jsonld.loader.DocumentLoaderOptions;

public class ContextLoader implements DocumentLoader {

    @Override
    public Document loadDocument(URI url, DocumentLoaderOptions options) throws JsonLdError {
        // TODO Auto-generated method stub
        return null;
    }

    public static DocumentLoader getInstance() {
        // TODO Auto-generated method stub
        return null;
    }

}
