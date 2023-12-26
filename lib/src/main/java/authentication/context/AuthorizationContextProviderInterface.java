package authentication.context;


import authentication.jwt.dto.TokenBody;

public interface AuthorizationContextProviderInterface<TContextObject, TAccessTokenPayloadObject, TRefreshTokenPayloadObject> {
    String getContextName();
    Class<TContextObject> getContextObjectClass();
    String getContextObjectId(TContextObject contextObject);
    TContextObject getContextObjectById(String id);
    Long getAccessTokenExpirationTime();
    Long getRefreshTokenExpirationTime();

    default Class<TAccessTokenPayloadObject> getAccessTokenPayloadClass() {
        return null;
    }

    default Class<TRefreshTokenPayloadObject> getRefreshTokenPayloadClass() {
        return null;
    }

    default TAccessTokenPayloadObject serializeAccessTokenPayload(TContextObject contextObject, TokenBody<TAccessTokenPayloadObject> tokenBody, Object extras)
    {
        return null;
    }

    default TRefreshTokenPayloadObject serializeRefreshTokenPayload(TContextObject contextObject, TokenBody<TRefreshTokenPayloadObject> tokenBody, Object extras)
    {
        return null;
    }
}
