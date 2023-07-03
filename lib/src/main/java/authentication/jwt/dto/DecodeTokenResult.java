package authentication.jwt.dto;

import org.apache.el.parser.Token;

public class DecodeTokenResult<T> {
    public boolean isTokenValid;
    public TokenBody<T> tokenBody;
    public Exception decodeException;
}
