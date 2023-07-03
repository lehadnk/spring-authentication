package authentication.jwt;

import org.springframework.context.annotation.Bean;

public class JwtBeanConfiguration {
    @Bean
    public JwtFactory createJwtFactory(
            JwtConfig jwtConfig
    ) {
        return new JwtFactory(jwtConfig.jwtSecret);
    }
}
