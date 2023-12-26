package authentication.refresh_token;

import authentication.access_token.AccessTokenService;
import authentication.context.AuthorizationContextProviderInterface;
import authentication.context.ContextService;
import authentication.jwt.JwtService;
import authentication.jwt.dto.TokenBody;
import authentication.jwt.dto.TokenType;
import authentication.refresh_token.dto.TokenExchangeResult;
import authentication.refresh_token.dto.ValidateRefreshTokenResult;
import authentication.token_storage.TokenStorageService;
import authentication.validation.ValidationService;

import java.sql.Date;
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

    public <TContextObject, TRefreshTokenPayloadObject> ValidateRefreshTokenResult<TContextObject, TRefreshTokenPayloadObject> validateRefreshToken(
            String contextName,
            String token
    ) {
        AuthorizationContextProviderInterface<TContextObject, ?, TRefreshTokenPayloadObject> context = this.contextService.getContextByName(contextName);
        var decodedToken = this.jwtService.decodeToken(token, context.getRefreshTokenPayloadClass());
        this.validationService.validateToken(token, decodedToken);

        var validateRefreshTokenResult = new ValidateRefreshTokenResult<TContextObject, TRefreshTokenPayloadObject>();
        if (!decodedToken.isTokenValid || !decodedToken.tokenBody.tokenType.equals(TokenType.REFRESH_TOKEN)) {
            validateRefreshTokenResult.isValid = false;
            return validateRefreshTokenResult;
        }

        var contextObject = context.getContextObjectById(decodedToken.tokenBody.id);
        validateRefreshTokenResult.isValid = true;
        validateRefreshTokenResult.contextObject = contextObject;
        validateRefreshTokenResult.tokenPayload = decodedToken.tokenBody.payload;
        return validateRefreshTokenResult;
    }

    public <TContextObject, TAccessTokenPayloadObject, TRefreshTokenPayloadObject> String issueRefreshToken(
            String contextName,
            TContextObject contextObject
    ) {
        return this.issueRefreshToken(contextName, contextObject, null);
    }

    public <TContextObject, TAccessTokenPayloadObject, TRefreshTokenPayloadObject> String issueRefreshToken(
            String contextName,
            TContextObject contextObject,
            Object extras
    ) {
        AuthorizationContextProviderInterface<TContextObject, TAccessTokenPayloadObject, TRefreshTokenPayloadObject> context = this.contextService.getContextByName(contextName);

        var tokenBody = new TokenBody<TRefreshTokenPayloadObject>();
        tokenBody.id = context.getContextObjectId(contextObject);
        tokenBody.expiresAt = Date.from(Instant.now().plus(context.getRefreshTokenExpirationTime(), java.time.temporal.ChronoUnit.SECONDS));
        tokenBody.context = contextName;
        tokenBody.tokenType = TokenType.REFRESH_TOKEN;
        tokenBody.payload = context.serializeRefreshTokenPayload(contextObject, tokenBody, extras);

        var tokenString = this.jwtService.encodeToken(tokenBody);
        this.tokenStorageService.addTokenToStorage(contextName, tokenString);

        return tokenString;
    }

    public <TContextObject, TAccessTokenPayloadObject, TRefreshTokenPayloadObject> TokenExchangeResult exchangeRefreshTokenForAuthorizationToken(
            String contextName,
            String refreshToken
    ) {
        return this.exchangeRefreshTokenForAuthorizationToken(contextName, refreshToken, null);
    }

    public <TContextObject, TAccessTokenPayloadObject, TRefreshTokenPayloadObject> TokenExchangeResult exchangeRefreshTokenForAuthorizationToken(
            String contextName,
            String refreshToken,
            Object extras
    ) {
        ValidateRefreshTokenResult<TContextObject, TRefreshTokenPayloadObject> validateTokenResult = this.validateRefreshToken(contextName, refreshToken);
        var tokenExchangeResult = new TokenExchangeResult();

        if (!validateTokenResult.isValid) {
            tokenExchangeResult.isSuccess = false;
            return tokenExchangeResult;
        }

        tokenExchangeResult.accessToken = this.accessTokenService.issueAccessToken(contextName, validateTokenResult.contextObject, extras);
        tokenExchangeResult.isSuccess = true;
        return tokenExchangeResult;
    }
}
