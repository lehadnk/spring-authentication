package authentication.validation;

import authentication.token_storage.TokenStorageService;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ValidationBeanConfiguration {
    public ValidationService createValidationService(
            TokenStorageService tokenStorageService
    ) {
        return new ValidationService(
                tokenStorageService
        );
    }
}
