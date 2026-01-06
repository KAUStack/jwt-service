package com.kaustack.jwt;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;

import lombok.RequiredArgsConstructor;

import java.util.Date;

@Component
@RequiredArgsConstructor
public class JwtGenerator {

    private JwtKeysProvider jwtKeysProvider;

    @Value("${jwt.expiration}")
    private long expiration;

    @Value("${jwt.issuer}")
    private String issuer;

    public String generateToken(String id, String name, String email, String gender) {
        return JWT.create()
                .withSubject(id)
                .withClaim("name", name)
                .withClaim("email", email)
                .withClaim("gender", gender)
                .withIssuer(issuer)
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + expiration))
                .sign(jwtKeysProvider.getAlgorithm());
    }
}
