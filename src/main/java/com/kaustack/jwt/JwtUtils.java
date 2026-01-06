package com.kaustack.jwt;

import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;

import lombok.RequiredArgsConstructor;

import java.util.Date;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class JwtUtils {

    private JwtKeysProvider jwtKeysProvider;
    
    private DecodedJWT decodeToken(String token) {
        return JWT.require(jwtKeysProvider.getAlgorithm())
                .build()
                .verify(token);
    }

    public String extractClaim(String token, String claimName) {
        return decodeToken(token).getClaim(claimName).asString();
    }

    public UUID extractUserId(String token) {
        String id = extractClaim(token, "subject");
        return UUID.fromString(id);
    }

    public boolean validateToken(String token) {
        try {
            DecodedJWT decoded = decodeToken(token);
            return !decoded.getExpiresAt().before(new Date());
        } catch (Exception e) {
            return false;
        }
    }
}
