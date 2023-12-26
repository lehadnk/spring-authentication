package authentication.refresh_token.dto;

public class ValidateRefreshTokenResult<TContextObject, TRefreshTokenPayloadObject> {
    public Boolean isValid;
    public TContextObject contextObject;
    public TRefreshTokenPayloadObject tokenPayload;
}
