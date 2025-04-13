package site.caboomlog.gatewayservice.jwt;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements GlobalFilter {

    private final WebClient.Builder webClientBuilder;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();
    private final JwtWhitelistProperties jwtWhitelistProperties;
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        boolean isWhiteListed = jwtWhitelistProperties.getJwt()
                .stream().anyMatch(allowed -> pathMatcher.match(allowed, path));

        if (HttpMethod.GET.equals(request.getMethod()) &&
                !(pathMatcher.match("/api/blogs/*/categories", path)
                || pathMatcher.match("/api/blogs/me", path)
                || pathMatcher.match("/api/blogs/*/members/me", path)
                || path.startsWith("/api/members")
                || pathMatcher.match("/api/blogs/*/posts/*", path))) {
            isWhiteListed = true;
        }
        if (pathMatcher.match("/api/blogs/*/posts/public", path)) {
            isWhiteListed = true;
        }

        if (isWhiteListed) {
            return chain.filter(exchange);
        }

        String authHeader = request.getHeaders().getFirst(AUTHORIZATION);
        if (((authHeader == null || !authHeader.startsWith("Bearer "))) &&
        !pathMatcher.match("/api/blogs/*/posts/*", path)) {
            exchange.getResponse().setStatusCode(UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = "";
        if (authHeader != null) {
            token = authHeader.replace("Bearer ", "");
        }
        return webClientBuilder.build()
                .post()
                .uri("http://token-service/token/validate")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(new TokenValidationRequest(token))
                .retrieve()
                .bodyToMono(TokenValidationResponse.class)
                .flatMap(response -> {
                    if (!response.isValid()) {
                        if (pathMatcher.match("/api/blogs/*/posts/*", path)) {
                            return chain.filter(exchange);
                        }
                        exchange.getResponse().setStatusCode(UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    }
                    ServerHttpRequest modifiedRequest = request.mutate()
                            .header("X-Caboomlog-UID", String.valueOf(response.getMbUuid()))
                            .build();
                    return chain.filter(exchange.mutate().request(modifiedRequest).build());
                })
                .onErrorResume(e -> {
                    log.error("",e);
                    exchange.getResponse().setStatusCode(UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                });
    }
}
