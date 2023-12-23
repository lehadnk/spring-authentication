package authentication.jwt.dto;

import java.util.Date;

public class TokenBody<T> {
    public String context;
    public String id;
    public TokenType tokenType;
    public Date expiresAt;
    public T payload;
}
