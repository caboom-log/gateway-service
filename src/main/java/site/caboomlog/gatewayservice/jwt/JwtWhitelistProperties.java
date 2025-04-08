package site.caboomlog.gatewayservice.jwt;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Getter
@Configuration
@ConfigurationProperties(prefix = "custom-filter.whitelist")
@Setter
public class JwtWhitelistProperties {
    private List<String> jwt;
}