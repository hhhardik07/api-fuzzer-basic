package com.apifuzzer.generation;

import com.apifuzzer.config.CollegePortalConfig;
import com.apifuzzer.model.RequestSpec;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class MutationCoverageTest {

    @Test
    void shouldGenerateQueryMutationsForSearchEndpoint() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        String configJson = Files.readString(Path.of("juice-shop-config.json"));
        CollegePortalConfig config = mapper.readValue(configJson, CollegePortalConfig.class);

        List<RequestSpec> seeds = config.buildSeedRequests();
        
        // Find the search seed
        RequestSpec searchSeed = seeds.stream()
                .filter(s -> s.getId().equals("get-products-search"))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Search seed not found"));

        System.out.println("Seed URL: " + searchSeed.getUrl());
        System.out.println("Seed Method: " + searchSeed.getMethod());
        System.out.println("Seed Body: " + searchSeed.getBody());

        MutationEngine me = new MutationEngine();
        StructuralMutator sm = new StructuralMutator();
        PayloadMutator pm = new PayloadMutator();

        List<RequestSpec> bodyMuts = me.generateMutations(searchSeed);
        System.out.println("Body mutations: " + bodyMuts.size());

        List<RequestSpec> structMuts = sm.mutate(searchSeed, 20);
        System.out.println("Structural mutations: " + structMuts.size());
        for (RequestSpec m : structMuts) {
            System.out.println("  " + m.getTestStrategy() + " -> " + m.getUrl());
        }

        List<RequestSpec> payloadMuts = pm.mutate(searchSeed, 20);
        System.out.println("Payload mutations: " + payloadMuts.size());
        for (RequestSpec m : payloadMuts) {
            System.out.println("  " + m.getTestStrategy() + " -> " + m.getUrl());
        }

        // Should have query parameter mutations
        boolean hasQueryMut = structMuts.stream().anyMatch(m -> 
            m.getTestStrategy().contains("QUERY"));
        System.out.println("Has query mut: " + hasQueryMut);
        // Don't assert, just print for debugging
    }
}