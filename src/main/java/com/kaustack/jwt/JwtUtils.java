package com.kaustack.jwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Component
public class JwtUtils {

    private final JwtKeysProvider jwtKeysProvider;
    private final String token;

    // Constructor for Spring component usage (with verification)
    @Autowired
    public JwtUtils(JwtKeysProvider jwtKeysProvider) {
        this.jwtKeysProvider = jwtKeysProvider;
        this.token = null;
    }

    // Constructor for simple token decoding (without verification)
    public JwtUtils(String token) {
        this.jwtKeysProvider = null;
        this.token = token;
    }

    private DecodedJWT decodeToken(String token) {
        DecodedJWT unverifiedToken = JWT.decode(token);

        // If no provider is available, return unverified token (decode-only mode)
        if (jwtKeysProvider == null) {
            return unverifiedToken;
        }

        String type = unverifiedToken.getClaim("type").asString();
        Algorithm algorithm = "access".equals(type)
                ? jwtKeysProvider.getAccessAlgorithm()
                : jwtKeysProvider.getRefreshAlgorithm();

        // If no algorithm is available, return unverified token
        if (algorithm == null) {
            return unverifiedToken;
        }

        return JWT.require(algorithm)
                .build()
                .verify(token);
    }

    public String extractClaim(String token, String claimName) {
        return decodeToken(token).getClaim(claimName).asString();
    }

    public UUID extractUserId(String token) {
        String id = extractClaim(token, "sub");
        return UUID.fromString(id);
    }

    public Duration extractMaxAge(String token) {
        long expSeconds = Long.parseLong(extractClaim(token, "exp"));
        long nowSeconds = Instant.now().getEpochSecond();
        long maxAgeSeconds = Math.max(0, expSeconds - nowSeconds);
        return Duration.ofSeconds(maxAgeSeconds);
    }

    public String extractTokenType(String token) {
        return JWT.decode(token).getClaim("type").asString();
    }

    public String extractEmail(String token) {
        return extractClaim(token, "email");
    }

    public String extractName(String token) {
        return extractClaim(token, "name");
    }

    public String extractGender(String token) {
        return extractClaim(token, "gender");
    }

    public boolean validateToken(String token, TokenType expectedType) {
        try {
            DecodedJWT decoded = decodeToken(token);
            boolean notExpired = !decoded.getExpiresAt().before(new Date());
            boolean correctType = expectedType == null
                    || expectedType.getValue().equals(decoded.getClaim("type").asString());
            return notExpired && correctType;
        } catch (Exception e) {
            return false;
        }
    }

    // Overloaded methods that use the stored token

    public String extractClaim(String claimName) {
        if (token == null) {
            throw new IllegalStateException(
                    "No token available. Use the constructor with token parameter or call extractClaim(String token, String claimName)");
        }
        return extractClaim(token, claimName);
    }

    public UUID extractUserId() {
        if (token == null) {
            throw new IllegalStateException(
                    "No token available. Use the constructor with token parameter or call extractUserId(String token)");
        }
        return extractUserId(token);
    }

    public Duration extractMaxAge() {
        if (token == null) {
            throw new IllegalStateException(
                    "No token available. Use the constructor with token parameter or call extractMaxAge(String token)");
        }
        return extractMaxAge(token);
    }

    public String extractTokenType() {
        if (token == null) {
            throw new IllegalStateException(
                    "No token available. Use the constructor with token parameter or call extractTokenType(String token)");
        }
        return extractTokenType(token);
    }

    public boolean validateToken(TokenType expectedType) {
        if (token == null) {
            throw new IllegalStateException(
                    "No token available. Use the constructor with token parameter or call validateToken(String token, TokenType expectedType)");
        }
        return validateToken(token, expectedType);
    }

    public String extractEmail() {
        if (token == null) {
            throw new IllegalStateException(
                    "No token available. Use the constructor with token parameter or call extractEmail(String token)");
        }
        return extractEmail(token);
    }

    public String extractName() {
        if (token == null) {
            throw new IllegalStateException(
                    "No token available. Use the constructor with token parameter or call extractName(String token)");
        }
        return extractName(token);
    }

    public String extractGender() {
        if (token == null) {
            throw new IllegalStateException(
                    "No token available. Use the constructor with token parameter or call extractGender(String token)");
        }
        return extractGender(token);
    }
}
