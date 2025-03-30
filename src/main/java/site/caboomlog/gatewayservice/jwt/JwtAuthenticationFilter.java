package site.caboomlog.gatewayservice.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements GlobalFilter {

    private final WebClient.Builder webClientBuilder;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        if (path.contains("/login") || path.contains("/signup") ||
                path.contains("/topic") || path.contains("refresh")) {
            return chain.filter(exchange);
        }

        String authHeader = request.getHeaders().getFirst(AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeader.replace("Bearer ", "");

        return webClientBuilder.build()
                .post()
                .uri("http://token-service/token/validate")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(new TokenValidationRequest(token))
                .retrieve()
                .bodyToMono(TokenValidationResponse.class)
                .flatMap(response -> {
                    if (!response.isValid()) {
                        exchange.getResponse().setStatusCode(UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    }

                    ServerHttpRequest modifiedRequest = request.mutate()
                            .header("caboomlog-mb-no", String.valueOf(response.getMbNo()))
                            .build();
                    return chain.filter(exchange.mutate().request(modifiedRequest).build());
                })
                .onErrorResume(e -> {
                    exchange.getResponse().setStatusCode(UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                });
    }
}
