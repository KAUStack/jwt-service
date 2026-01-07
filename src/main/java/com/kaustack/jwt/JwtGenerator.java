package com.kaustack.jwt;

import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import lombok.RequiredArgsConstructor;

import java.util.Date;



@Component
@RequiredArgsConstructor
public class JwtGenerator {

        private final JwtKeysProvider jwtKeysProvider;
        private final JwtProperties jwtProperties;

        public String generateToken(TokenType type, String id, String name, String email, String gender) {
                long expiration = type == TokenType.ACCESS
                                ? jwtProperties.getAccessToken().getExpiration()
                                : jwtProperties.getRefreshToken().getExpiration();

                var jwtBuilder = JWT.create()
                                .withSubject(id)
                                .withClaim("type", type.getValue())
                                .withIssuer(jwtProperties.getIssuer())
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
