package com.kaustack.jwt;

import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import lombok.RequiredArgsConstructor;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class JwtUtils {

    private final JwtKeysProvider jwtKeysProvider;

    private DecodedJWT decodeToken(String token) {

        DecodedJWT unverifiedToken = JWT.decode(token);
        String type = unverifiedToken.getClaim("type").asString();

        Algorithm algorithm = "access".equals(type)
                ? jwtKeysProvider.getAccessAlgorithm()
                : jwtKeysProvider.getRefreshAlgorithm();

        // If no algorithm is available (decode-only mode), return unverified token
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
}
