package com.kaustack.jwt;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;

@AutoConfiguration
@EnableConfigurationProperties(JwtProperties.class)
@ComponentScan(basePackages = "com.kaustack.jwt")
public class JwtAutoConfiguration {
}
