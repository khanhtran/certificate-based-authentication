package com.sample.auth;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

import jakarta.servlet.http.HttpServletRequest;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Map;

@SpringBootApplication
public class IdentityProviderApplication {

    public static void main(String[] args) {
        SpringApplication.run(IdentityProviderApplication.class, args);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .x509(x509 -> x509.subjectPrincipalRegex("CN=(.*?),"))
                .securityContext(securityContext -> securityContext.requireExplicitSave(false)); // Avoid CSRF in stateless applications
        return http.build();
    }

    @Bean
    public JwtEncoder jwtEncoder() throws Exception {
        // Generate an RSA key pair
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        System.out.println("publicKey: " + publicKey.toString());
        // Create the JWK for the RSA key pair
        JWK jwk = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .build();

        // Create a JWKSource that contains the JWK
        JWKSource jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));

        // Return the JwtEncoder that uses the JWKSource
        return new NimbusJwtEncoder(jwkSource);
    }
}

@RestController
class TokenController {

    private final JwtEncoder jwtEncoder;

    public TokenController(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }

    @PostMapping("/oauth/token")
    public Map<String, String> getToken(HttpServletRequest request) throws SSLPeerUnverifiedException {
        SSLSession sslSession = (SSLSession) request.getAttribute("javax.servlet.request.ssl_session");
        if (sslSession == null) {
            throw new RuntimeException("No SSL session found");
        }

        X509Certificate[] certChain = (X509Certificate[]) sslSession.getPeerCertificates();
        if (certChain == null || certChain.length == 0) {
            throw new RuntimeException("Client certificate not found");
        }

        String subject = certChain[0].getSubjectDN().getName();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .subject(subject)
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .claim("cn", subject)
                .build();

        String token = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
        return Map.of("access_token", token);
    }
}

