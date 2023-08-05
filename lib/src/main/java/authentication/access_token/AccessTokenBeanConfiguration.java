package authentication.access_token;

import authentication.context.ContextService;
import authentication.jwt.JwtService;
import authentication.token_storage.TokenStorageService;
import authentication.validation.ValidationService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AccessTokenBeanConfiguration {
    @Bean
    public AccessTokenService createAccessTokenService(
            JwtService jwtService,
            ContextService contextService,
            TokenStorageService tokenStorageService,
            ValidationService validationService
    ) {
        return new AccessTokenService(
                jwtService,
                contextService,
                tokenStorageService,
                validationService
        );
    }
}
