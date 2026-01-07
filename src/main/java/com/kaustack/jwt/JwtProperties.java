package com.kaustack.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Data;

/**
 * Configuration properties for JWT token generation and validation.
 * Override these in your application.properties using the "jwt" prefix.
 */
@Data
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {

    private TokenConfig accessToken = new TokenConfig();
    private TokenConfig refreshToken = new TokenConfig();
    private String issuer;

    @Data
    public static class TokenConfig {
        private String privateKey;
        private String publicKey;
        private Long expiration;
    }
}
