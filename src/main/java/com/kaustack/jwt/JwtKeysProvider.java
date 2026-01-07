package com.kaustack.jwt;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.auth0.jwt.algorithms.Algorithm;

import lombok.Getter;

import jakarta.annotation.PostConstruct;

import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Component
class JwtKeysProvider {

    @Getter
    private Algorithm accessAlgorithm;
    @Getter
    private Algorithm refreshAlgorithm;

    @Value("${jwt.access-token.private-key}")
    private String accessPrivateKeyStr;
    @Value("${jwt.access-token.public-key}")
    private String accessPublicKeyStr;

    @Value("${jwt.refresh-token.private-key}")
    private String refreshPrivateKeyStr;
    @Value("${jwt.refresh-token.public-key}")
    private String refreshPublicKeyStr;

    @PostConstruct
    public void init() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("EC");

        this.accessAlgorithm = loadAlgorithm(kf, accessPrivateKeyStr, accessPublicKeyStr);
        this.refreshAlgorithm = loadAlgorithm(kf, refreshPrivateKeyStr, refreshPublicKeyStr);
    }

    private Algorithm loadAlgorithm(KeyFactory kf, String privateKeyStr, String publicKeyStr) throws Exception {
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyStr);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        ECPrivateKey privateKey = (ECPrivateKey) kf.generatePrivate(privateKeySpec);

        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyStr);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        ECPublicKey publicKey = (ECPublicKey) kf.generatePublic(publicKeySpec);

        return Algorithm.ECDSA256(publicKey, privateKey);
    }

}
