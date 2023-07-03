package authentication.jwt.business;

import authentication.jwt.dto.DecodeTokenResult;
import authentication.jwt.dto.TokenBody;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;

public class TokenDecoder<T> {
    private final JwtParser jwtParser;

    public TokenDecoder(
            JwtParser jwtParser
    ) {
        this.jwtParser = jwtParser;
    }

    public DecodeTokenResult<T> decode(String token, TypeReference<TokenBody<T>> tokenBodyTypeReference) {
        var subject = this.jwtParser.parseClaimsJws(token).getBody().getSubject();
        var result = new DecodeTokenResult<T>();
        var objectMapper = new ObjectMapper();

        try {
            var tokenBody = objectMapper.readValue(subject, tokenBodyTypeReference);
            result.isTokenValid = true;
            result.tokenBody = tokenBody;
        } catch (JsonProcessingException | MalformedJwtException e) {
            result.isTokenValid = false;
            result.decodeException = e;
        }

        return result;
    }
}
