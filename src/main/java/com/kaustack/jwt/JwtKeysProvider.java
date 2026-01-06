package com.kaustack.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Component
public class JwtKeysProvider {

    @Getter
    private Algorithm algorithm;

    private ECPrivateKey privateKey;
    private ECPublicKey publicKey;

    @Value("${jwt.private-key}")
    private String privateKeyStr;
    @Value("${jwt.public-key}")
    private String publicKeyStr;

    @PostConstruct
    public void init() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("EC");
        
        // Load private key
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyStr);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        this.privateKey = (ECPrivateKey) kf.generatePrivate(privateKeySpec);
        
        // Load public key
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyStr);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        this.publicKey = (ECPublicKey) kf.generatePublic(publicKeySpec);
        
        this.algorithm = Algorithm.ECDSA256(publicKey, privateKey);
    }

}
