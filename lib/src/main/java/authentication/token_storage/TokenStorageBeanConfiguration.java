package authentication.token_storage;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class TokenStorageBeanConfiguration {
    @Bean
    public TokenStorageService createTokenStorageService(
            TokenStorageInterface tokenStorage
    ) {
        return new TokenStorageService(
                tokenStorage
        );
    }
}
