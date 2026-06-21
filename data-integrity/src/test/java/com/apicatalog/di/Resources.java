package com.apicatalog.di;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.IOException;
import java.util.Map;
import java.util.stream.Stream;

import com.apicatalog.tree.io.TreeIOException;
import com.apicatalog.tree.io.jakcson.Jackson2Reader;
import com.fasterxml.jackson.core.JsonFactory;

class Resources {

    @SuppressWarnings("unchecked")
    static <T> Map<String, T> getMap(String name) throws TreeIOException, IOException {
        var reader = new Jackson2Reader(new JsonFactory());

        try (var is = new BufferedInputStream(Resources.class.getResourceAsStream(name))) {
            var input = reader.read(is);
            if (input instanceof Map map) {
                return (Map<String, T>) map;
            }
            throw new IllegalStateException();
        }
    }

    static final Stream<String> stream() throws TreeIOException {
        return Stream.of(new File(Resources.class.getResource("").getPath()).listFiles())
                .filter(File::isFile)
                .map(File::getName);
    }

}
