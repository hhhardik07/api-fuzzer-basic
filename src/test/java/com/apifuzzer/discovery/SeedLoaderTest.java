
package com.apifuzzer.discovery;

import com.apifuzzer.config.FuzzerConfig;
import com.apifuzzer.model.RequestSpec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SeedLoaderTest {

    @TempDir
    Path tempDir;

    private Path createManifest(String json) throws Exception {
        Path file = tempDir.resolve("manifest.json");
        Files.writeString(file, json);
        return file;
    }

    @Test
    void shouldLoadValidManifest() throws Exception {

        String json = """
                [
                  {
                    "id": "get-profile",
                    "method": "GET",
                    "url": "http://localhost:8765/api/profile",
                    "headers": {
                      "Accept": "application/json"
                    },
                    "body": null,
                    "testStrategy": "BASELINE"
                  }
                ]
                """;

        SeedLoader loader = new SeedLoader(new FuzzerConfig());

        List<RequestSpec> requests = loader.load(
                createManifest(json)
        );

        assertEquals(1, requests.size());
        assertEquals("get-profile", requests.get(0).getId());
        assertEquals("GET", requests.get(0).getMethod());
        assertEquals("BASELINE", requests.get(0).getTestStrategy());
    }

    @Test
    void shouldRejectDuplicateRequestIds() throws Exception {

        String json = """
                [
                  {
                    "id": "duplicate",
                    "method": "GET",
                    "url": "http://localhost:8765/api/one"
                  },
                  {
                    "id": "duplicate",
                    "method": "GET",
                    "url": "http://localhost:8765/api/two"
                  }
                ]
                """;

        SeedLoader loader = new SeedLoader(new FuzzerConfig());

        assertThrows(
                IllegalArgumentException.class,
                () -> loader.load(createManifest(json))
        );
    }

    @Test
    void shouldRejectUnsupportedMethods() throws Exception {

        String json = """
                [
                  {
                    "id": "bad-method",
                    "method": "TRACE",
                    "url": "http://localhost:8765/api/test"
                  }
                ]
                """;

        SeedLoader loader = new SeedLoader(new FuzzerConfig());

        assertThrows(
                IllegalArgumentException.class,
                () -> loader.load(createManifest(json))
        );
    }

    @Test
    void shouldRejectInvalidUrls() throws Exception {

        String json = """
                [
                  {
                    "id": "bad-url",
                    "method": "GET",
                    "url": "not-a-valid-url"
                  }
                ]
                """;

        SeedLoader loader = new SeedLoader(new FuzzerConfig());

        assertThrows(
                IllegalArgumentException.class,
                () -> loader.load(createManifest(json))
        );
    }

    @Test
    void shouldRejectEmptyManifest() throws Exception {

        SeedLoader loader = new SeedLoader(new FuzzerConfig());

        assertThrows(
                IllegalArgumentException.class,
                () -> loader.load(createManifest("[]"))
        );
    }
}

