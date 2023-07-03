package authentication.jwt.business;

import authentication.jwt.dto.TokenBody;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.JwtBuilder;

public class TokenEncoder<T> {
    private final JwtBuilder jwtBuilder;

    public TokenEncoder(
            JwtBuilder jwtBuilder
    ) {
        this.jwtBuilder = jwtBuilder;
    }

    public String encodeToken(TokenBody<T> tokenBody)
    {
        var mapper = new ObjectMapper();
        try {
            var subject = mapper.writeValueAsString(tokenBody);
            return this.jwtBuilder.setSubject(subject).compact();
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}
