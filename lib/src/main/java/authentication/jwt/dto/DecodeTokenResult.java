package authentication.jwt.dto;

public class DecodeTokenResult<T> {
    public boolean isTokenValid;
    public boolean isTokenExpired = false;
    public TokenBody<T> tokenBody;
    public Exception decodeException;
}
