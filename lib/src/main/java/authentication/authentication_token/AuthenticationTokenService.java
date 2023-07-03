package authentication.authentication_token;

import authentication.context.AuthorizationContextProviderInterface;
import authentication.context.ContextService;
import authentication.jwt.JwtService;
import authentication.jwt.dto.TokenBody;
import authentication.jwt.dto.TokenType;
import authentication.token_storage.TokenStorageService;

import java.time.Instant;

public class AuthenticationTokenService {
    private final JwtService jwtService;
    private final ContextService contextService;
    private final TokenStorageService tokenStorageService;

    public AuthenticationTokenService(
            JwtService jwtService,
            ContextService contextService,
            TokenStorageService tokenStorageService
    ) {
        this.jwtService = jwtService;
        this.contextService = contextService;
        this.tokenStorageService = tokenStorageService;
    }

    public <TContextObject, TAccessTokenPayloadObject> String issueAccessToken(String contextName, TContextObject contextObject)
    {
        AuthorizationContextProviderInterface<TContextObject, TAccessTokenPayloadObject, ?> context = this.contextService.getContextByName(contextName);

        var tokenBody = new TokenBody<>();
        tokenBody.id = context.getContextObjectId(contextObject);
        tokenBody.expiresAt = (Instant.now().toEpochMilli() / 1000) + context.getAccessTokenExpirationTime();
        tokenBody.context = contextName;
        tokenBody.payload = context.serializeAccessTokenPayload(contextObject);
        tokenBody.tokenType = TokenType.ACCESS_TOKEN;

        var tokenString = this.jwtService.encodeToken(tokenBody);
        this.tokenStorageService.addTokenToStorage(contextName, tokenString);

        return tokenString;
    }
}
