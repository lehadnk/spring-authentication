package authentication.jwt;

import org.springframework.beans.factory.annotation.Value;

public class JwtConfig {
    @Value("${authentication.jwt.secret}")
    public String jwtSecret;
}