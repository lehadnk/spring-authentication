package authentication.context;


public interface AuthorizationContextProviderInterface<TContextObject, TAccessTokenPayloadObject, TRefreshTokenPayloadObject> {
    String getContextName();
    Class<TContextObject> getContextObjectClass();
    String getContextObjectId(TContextObject contextObject);
    TContextObject getContextObjectById(String id);
    Long getAccessTokenExpirationTime();
    Long getRefreshTokenExpirationTime();

    default Class<TAccessTokenPayloadObject> getPayloadClass() {
        return null;
    }

    default TAccessTokenPayloadObject serializeAccessTokenPayload(TContextObject contextObject)
    {
        return null;
    }

    default TRefreshTokenPayloadObject serializeRefreshTokenPayload(TContextObject contextObject)
    {
        return null;
    }
}
