package authentication.jwt;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtBeanConfiguration {
    @Bean
    public JwtService createJwtService(
            JwtFactory jwtFactory
    ) {
        return new JwtService(jwtFactory);
    }

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
