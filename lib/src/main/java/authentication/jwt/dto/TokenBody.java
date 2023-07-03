package authentication.jwt.dto;

public class TokenBody<T> {
    public String context;
    public String id;
    public TokenType tokenType;
    public Long expiresAt;
    public T payload;
}
