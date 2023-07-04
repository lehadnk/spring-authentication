package authentication.access_token;

import authentication.access_token.dto.ValidateAccessTokenResult;
import authentication.context.AuthorizationContextProviderInterface;
import authentication.context.ContextService;
import authentication.jwt.JwtService;
import authentication.jwt.dto.TokenBody;
import authentication.jwt.dto.TokenType;
import authentication.token_storage.TokenStorageService;
import authentication.validation.ValidationService;
import com.fasterxml.jackson.core.type.TypeReference;

import java.time.Instant;

public class AccessTokenService {
    private final JwtService jwtService;
    private final ContextService contextService;
    private final TokenStorageService tokenStorageService;
    private final ValidationService validationService;

    public AccessTokenService(
            JwtService jwtService,
            ContextService contextService,
            TokenStorageService tokenStorageService,
            ValidationService validationService
    ) {
        this.jwtService = jwtService;
        this.contextService = contextService;
        this.tokenStorageService = tokenStorageService;
        this.validationService = validationService;
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

    public <TTokenBodyType, TContextObjectType> ValidateAccessTokenResult<TContextObjectType> validateAuthenticationToken(String contextName, String token, TypeReference<TokenBody<TTokenBodyType>> tokenBodyTypeReference)
    {
        var decodeTokenResult = this.jwtService.decodeToken(token, tokenBodyTypeReference);
        this.validationService.validateToken(token, decodeTokenResult);

        var validateAccessTokenResult = new ValidateAccessTokenResult<TContextObjectType>();
        if (decodeTokenResult.isTokenValid) {
            validateAccessTokenResult.isValid = true;
            AuthorizationContextProviderInterface<TContextObjectType, ?, ?> context = this.contextService.getContextByName(contextName);
            validateAccessTokenResult.contextObject = context.getContextObjectById(decodeTokenResult.tokenBody.id);
        } else {
            validateAccessTokenResult.isValid = false;
        }

        return validateAccessTokenResult;
    }
}
