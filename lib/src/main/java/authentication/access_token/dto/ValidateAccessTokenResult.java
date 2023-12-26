package authentication.access_token.dto;

public class ValidateAccessTokenResult<TContextObject, TAccessTokenPayloadObject> {
    public Boolean isValid;
    public Boolean isExpired = false;
    public TContextObject contextObject;
    public TAccessTokenPayloadObject tokenPayload;
}
