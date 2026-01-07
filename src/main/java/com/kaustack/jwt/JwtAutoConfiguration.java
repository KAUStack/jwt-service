package com.kaustack.jwt;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;

@AutoConfiguration
@EnableConfigurationProperties(JwtProperties.class)
@ComponentScan(basePackages = "com.kaustack.jwt")
public class JwtAutoConfiguration {

    // JwtGenerator is only created when private keys are configured
    @Bean
    @ConditionalOnProperty(name = { "jwt.access-token.private-key" })
    public JwtGenerator jwtGenerator(JwtKeysProvider jwtKeysProvider, JwtProperties jwtProperties) {
        return new JwtGenerator(jwtKeysProvider, jwtProperties);
    }
}
