package com.sample.auth;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.security.KeyStore;
import java.util.Map;

@SpringBootApplication
public class ClientApplication implements CommandLineRunner {

    public static void main(String[] args) {
        SpringApplication.run(ClientApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        // Load client certificate from keystore
//        ClassPathResource resource = new ClassPathResource("client.p12");
//        KeyStore keyStore = KeyStore.getInstance("PKCS12");
//        keyStore.load(resource.getInputStream(), "password".toCharArray());
//
//        // Set up SSL context with the client certificate
//        SSLContext sslContext = SSLContext.getInstance("TLS");
//        sslContext.init(null, null, null);
//
//        SSLParameters sslParameters = sslContext.getDefaultSSLParameters();
//        sslParameters.setNeedClientAuth(true);

        // Request JWT token from IdP
        WebClient webClient = WebClient.builder()
                .baseUrl("https://localhost:8443") // Identity Provider
                .build();

        Map<String, String> tokenResponse = webClient.post()
                .uri("/oauth/token")
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .bodyToMono(Map.class)
                .block();

        System.out.println("tokenResponse: " + tokenResponse);
        if (tokenResponse != null && tokenResponse.containsKey("access_token")) {
            String jwtToken = tokenResponse.get("access_token");

            // Call the protected API with the JWT token
            WebClient apiClient = WebClient.builder()
                    .baseUrl("http://localhost:8081") // Protected API Server
                    .defaultHeader("Authorization", "Bearer " + jwtToken)
                    .build();

            String response = apiClient.get()
                    .uri("/api/protected")
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();

            System.out.println("Response from protected API: " + response);
        } else {
            System.out.println("Failed to obtain JWT token from Identity Provider.");
        }
    }
}
