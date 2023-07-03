package authentication.context;

import authentication.context.exceptions.AuthorizationContextInitializationException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class ContextBeanConfiguration {
    @Bean
    public ContextService createContextService(
            List<AuthorizationContextProviderInterface<?, ?, ?>> contextProviders
    ) throws AuthorizationContextInitializationException {
        return new ContextService(
                contextProviders
        );
    }
}
