package com.example.bookapigateway.Security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import jakarta.ws.rs.core.HttpHeaders;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Service
public class JwtAuthenticationGatewayFilter implements GlobalFilter {

    @Value("${jwt.secret-key}")
    private String secretKey;
    private static final List<String> WHITELIST = List.of(
            "/public",
            "/actuator/health",
            "/swagger-ui",
            "/swagger-ui.html",
            "/v1"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        if (isWhitelisted(path)) {
            return chain.filter(exchange);
        }
        // 1) Extract Authorization header
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);

            try {
                Claims claims = Jwts.parser()
                        .setSigningKey(secretKey)
                        .parseClaimsJws(token)
                        .getBody();

                // Token is valid; you can extract e.g. roles/email
                String email = (String) claims.get("email");
                // etc.

                // Optionally add info to a request header for the microservice
                ServerHttpRequest newRequest = exchange.getRequest().mutate()
                        .header("X-User-Email", email)
                        .build();

                return chain.filter(exchange.mutate().request(newRequest).build());
            } catch (JwtException e) {
                // Token invalid or expired
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }
        } else {
            // No token, or doesn't start with Bearer
            // Decide if you want to allow or deny. Typically, deny or
            // allow for certain public endpoints
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }
    private boolean isWhitelisted(String path) {
        // A quick way is to check if path starts with or matches a pattern
        // For more advanced matching, use Spring's AntPathMatcher
        for (String w : WHITELIST) {
            if (path.startsWith(w)) {
                return true;
            }
        }
        return false;
    }
}

