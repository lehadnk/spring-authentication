package authentication.refresh_token;

import authentication.access_token.AccessTokenService;
import authentication.context.ContextService;
import authentication.jwt.JwtService;
import authentication.token_storage.TokenStorageService;
import authentication.validation.ValidationService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RefreshTokenBeanConfiguration {
    @Bean
    public RefreshTokenService createRefreshTokenService(
            ContextService contextService,
            JwtService jwtService,
            AccessTokenService accessTokenService,
            ValidationService validationService,
            TokenStorageService tokenStorageService
    )
    {
        return new RefreshTokenService(
                contextService,
                jwtService,
                accessTokenService,
                validationService,
                tokenStorageService
        );
    }
}
