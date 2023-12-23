package authentication.jwt.business;

import authentication.jwt.dto.TokenBody;
import io.jsonwebtoken.JwtBuilder;

import java.time.Instant;
import java.util.Date;

public class TokenEncoder<T> {
    private final JwtBuilder jwtBuilder;

    public TokenEncoder(
            JwtBuilder jwtBuilder
    ) {
        this.jwtBuilder = jwtBuilder;
    }

    public String encodeToken(TokenBody<T> tokenBody)
    {
        return this.jwtBuilder
                .expiration(tokenBody.expiresAt)
                .subject(tokenBody.id)
                .issuedAt(Date.from(Instant.now()))
                .audience().add(tokenBody.context).and()
                .claim("tokenType", tokenBody.tokenType)
                .claim("payload", tokenBody.payload)
                .compact();
    }
}
