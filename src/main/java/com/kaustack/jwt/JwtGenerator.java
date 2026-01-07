package com.kaustack.jwt;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import lombok.RequiredArgsConstructor;

import java.util.Date;

@Component
@RequiredArgsConstructor
public class JwtGenerator {

    private JwtKeysProvider jwtKeysProvider;

    @Value("${jwt.access-token.expiration}")
    private long accessTokenExpiration;

    @Value("${jwt.refresh-token.expiration}")
    private long refreshTokenExpiration;

    @Value("${jwt.issuer}")
    private String issuer;

    public String generateToken(TokenType type, String id, String name, String email, String gender) {
        long expiration = type == TokenType.ACCESS ? accessTokenExpiration : refreshTokenExpiration;

        var jwtBuilder = JWT.create()
                .withSubject(id)
                .withClaim("type", type.getValue())
                .withIssuer(issuer)
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + expiration));

        if (type == TokenType.ACCESS) {
            jwtBuilder
                    .withClaim("name", name)
                    .withClaim("email", email)
                    .withClaim("gender", gender);
        }

        Algorithm algorithm = type == TokenType.ACCESS
                ? jwtKeysProvider.getAccessAlgorithm()
                : jwtKeysProvider.getRefreshAlgorithm();

        return jwtBuilder.sign(algorithm);
    }
}
