package authentication;

import authentication.app.UserAuthorizationContext;
import authentication.authentication_token.AuthenticationTokenService;
import authentication.context.AuthorizationContextProviderInterface;
import authentication.context.ContextService;
import authentication.context.exceptions.AuthorizationContextInitializationException;
import authentication.jwt.JwtFactory;
import authentication.jwt.JwtService;
import authentication.refresh_token.RefreshTokenService;
import authentication.token_storage.InMemoryTokenStorage;
import authentication.token_storage.TokenStorageService;
import authentication.validation.ValidationService;

import java.util.ArrayList;
import java.util.List;

public class TestFactory {
    public JwtFactory createJwtFactory()
    {
        return new JwtFactory("qwe123qwe123qwe123qwe123qwe123qwe123qwe123qwe123");
    }

    public JwtService createJwtService()
    {
        return new JwtService(
                this.createJwtFactory()
        );
    }

    public List<AuthorizationContextProviderInterface<?, ?, ?>> createTestContextProvider()
    {
        var contextProvidersList = new ArrayList<AuthorizationContextProviderInterface<?, ?, ?>>(1);
        contextProvidersList.add(new UserAuthorizationContext());
        return contextProvidersList;
    }

    public ContextService createContextService()
    {
        try {
            return new ContextService(
                    this.createTestContextProvider()
            );
        } catch (AuthorizationContextInitializationException e) {
            throw new RuntimeException(e);
        }
    }

    public AuthenticationTokenService createAuthenticationTokenService()
    {
        return new AuthenticationTokenService(
                this.createJwtService(),
                this.createContextService(),
                this.createTokenStorageService()
        );
    }

    public ValidationService createValidationService()
    {
        return new ValidationService(
                this.createTokenStorageService()
        );
    }

    public RefreshTokenService createRefreshTokenService()
    {
        return new RefreshTokenService(
                this.createContextService(),
                this.createJwtService(),
                this.createAuthenticationTokenService(),
                this.createValidationService(),
                this.createTokenStorageService()
        );
    }

    public TokenStorageService createTokenStorageService()
    {
        return new TokenStorageService(
                new InMemoryTokenStorage()
        );
    }
}
