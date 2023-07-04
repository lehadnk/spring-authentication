package authentication.jwt;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtBeanConfiguration {
    @Bean
    public JwtFactory createJwtFactory(
            JwtConfig jwtConfig
    ) {
        return new JwtFactory(jwtConfig.jwtSecret);
    }

    @Bean
    public JwtConfig createJwtConfig() {
        return new JwtConfig();
    }
}
