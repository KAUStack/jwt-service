package com.kaustack.jwt;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Test;

class JwtUtilsTest {

    /**
     * Builds an unsigned token for decode-only mode. The signature segment is
     * arbitrary because {@link JwtUtils#JwtUtils(String)} never verifies it.
     */
    private static String tokenWithPayload(String payloadJson) {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String header = encoder.encodeToString(
                "{\"alg\":\"ES256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String payload = encoder.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + ".c2lnbmF0dXJl";
    }

    @Test
    void extractFlagsReturnsEmptyListWhenArrayContainsObjectElement() {
        String token = tokenWithPayload("{\"type\":\"access\",\"flags\":[\"beta\",{\"role\":\"admin\"}]}");

        assertEquals(List.of(), new JwtUtils(token).extractFlags());
    }

    @Test
    void extractFlagsReturnsStringFlags() {
        String token = tokenWithPayload("{\"type\":\"access\",\"flags\":[\"beta\",\"internal\"]}");

        assertEquals(List.of("beta", "internal"), new JwtUtils(token).extractFlags());
    }

    @Test
    void extractFlagsReturnsEmptyListWhenClaimIsMissing() {
        String token = tokenWithPayload("{\"type\":\"access\"}");

        assertEquals(List.of(), new JwtUtils(token).extractFlags());
    }
}
