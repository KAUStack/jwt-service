package com.kaustack.jwt;

import org.springframework.stereotype.Component;

import com.auth0.jwt.algorithms.Algorithm;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import jakarta.annotation.PostConstruct;

import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Component
@RequiredArgsConstructor
class JwtKeysProvider {

    private final JwtProperties jwtProperties;

    @Getter
    private Algorithm accessAlgorithm;
    @Getter
    private Algorithm refreshAlgorithm;

    @PostConstruct
    public void init() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("EC");

        this.accessAlgorithm = loadAlgorithm(
                kf,
                jwtProperties.getAccessToken().getPrivateKey(),
                jwtProperties.getAccessToken().getPublicKey());
        this.refreshAlgorithm = loadAlgorithm(
                kf,
                jwtProperties.getRefreshToken().getPrivateKey(),
                jwtProperties.getRefreshToken().getPublicKey());
    }

    private Algorithm loadAlgorithm(KeyFactory kf, String privateKeyStr, String publicKeyStr) throws Exception {
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyStr);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        ECPublicKey publicKey = (ECPublicKey) kf.generatePublic(publicKeySpec);

        // Return algorithm with public key only if no private key provided
        if (privateKeyStr == null || privateKeyStr.trim().isEmpty()) {
            return Algorithm.ECDSA256(publicKey, null);
        }

        // Return algorithm with both keys
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyStr);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        ECPrivateKey privateKey = (ECPrivateKey) kf.generatePrivate(privateKeySpec);

        return Algorithm.ECDSA256(publicKey, privateKey);
    }

}
