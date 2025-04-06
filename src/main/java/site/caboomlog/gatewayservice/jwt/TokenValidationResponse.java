package site.caboomlog.gatewayservice.jwt;

import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Getter
public class TokenValidationResponse {
    private boolean valid;
    private String mbUuid;
}
