package authentication.refresh_token;

import authentication.access_token.AccessTokenService;
import authentication.context.AuthorizationContextProviderInterface;
import authentication.context.ContextService;
import authentication.jwt.JwtService;
import authentication.jwt.dto.TokenBody;
import authentication.jwt.dto.TokenType;
import authentication.refresh_token.dto.TokenExchangeResult;
import authentication.token_storage.TokenStorageService;
import authentication.validation.ValidationService;
import com.fasterxml.jackson.core.type.TypeReference;

import java.time.Instant;

public class RefreshTokenService {
    private final ContextService contextService;
    private final JwtService jwtService;
    private final AccessTokenService accessTokenService;
    private final ValidationService validationService;
    private final TokenStorageService tokenStorageService;

    public RefreshTokenService(
            ContextService contextService,
            JwtService jwtService,
            AccessTokenService accessTokenService,
            ValidationService validationService,
            TokenStorageService tokenStorageService
    ) {
        this.contextService = contextService;
        this.jwtService = jwtService;
        this.accessTokenService = accessTokenService;
        this.validationService = validationService;
        this.tokenStorageService = tokenStorageService;
    }

    public <TContextObject, TAccessTokenPayloadObject, TRefreshTokenPayloadObject> String issueRefreshToken(
            String contextName,
            TContextObject contextObject
    ) {
        AuthorizationContextProviderInterface<TContextObject, TAccessTokenPayloadObject, TRefreshTokenPayloadObject> context = this.contextService.getContextByName(contextName);

        var tokenBody = new TokenBody<>();
        tokenBody.id = context.getContextObjectId(contextObject);
        tokenBody.expiresAt = (Instant.now().toEpochMilli() / 1000) + context.getRefreshTokenExpirationTime();
        tokenBody.context = contextName;
        tokenBody.payload = context.serializeRefreshTokenPayload(contextObject);
        tokenBody.tokenType = TokenType.REFRESH_TOKEN;

        var tokenString = this.jwtService.encodeToken(tokenBody);
        this.tokenStorageService.addTokenToStorage(contextName, tokenString);

        return tokenString;
    }

    public <TContextObject, TAccessTokenPayloadObject, TRefreshTokenPayloadObject> TokenExchangeResult exchangeRefreshTokenForAuthorizationToken(
            String contextName,
            String refreshToken,
            TypeReference<TokenBody<TRefreshTokenPayloadObject>> tokenBodyTypeReference
    ) {
        AuthorizationContextProviderInterface<TContextObject, TAccessTokenPayloadObject, TRefreshTokenPayloadObject> context = this.contextService.getContextByName(contextName);
        var decodedToken = this.jwtService.decodeToken(refreshToken, tokenBodyTypeReference);
        this.validationService.validateToken(refreshToken, decodedToken);

        var tokenExchangeResult = new TokenExchangeResult();
        if (!decodedToken.isTokenValid) {
            tokenExchangeResult.isSuccess = false;
            return tokenExchangeResult;
        }

        var contextObject = context.getContextObjectById(decodedToken.tokenBody.id);
        tokenExchangeResult.accessToken = this.accessTokenService.issueAccessToken(contextName, contextObject);
        tokenExchangeResult.isSuccess = true;
        return tokenExchangeResult;
    }
}
