package site.caboomlog.gatewayservice.jwt;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class TokenValidationRequest {
    private String token;
}
