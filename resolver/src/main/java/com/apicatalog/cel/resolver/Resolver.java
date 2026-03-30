package com.apicatalog.cel.resolver;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class Resolver {

    
    public Map<String, Object> resolve(String did) {
        
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {

            List<Future<String>> futures = List.of(
                executor.submit(() -> task1("1")),
                executor.submit(() -> task1("2")),
                executor.submit(() -> task1("3"))
            );

            for (Future<String> f : futures) {
                String result = f.get();  // ✅ waits
                System.out.println(result);
            }
            
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (ExecutionException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }        
        return null;

    }
    
    public String task1(String id) {
        System.out.println(id);
        return id + ":" + Instant.now().toString();
    }
    
    public static void main(String[] args) {
        new Resolver().resolve(null);
    }
    
}
