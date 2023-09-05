package authentication.jwt.business;

import authentication.jwt.dto.DecodeTokenResult;
import authentication.jwt.dto.TokenBody;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.DecodingException;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.security.WeakKeyException;

public class TokenDecoder<T> {
    private final JwtParser jwtParser;

    public TokenDecoder(
            JwtParser jwtParser
    ) {
        this.jwtParser = jwtParser;
    }

    public DecodeTokenResult<T> decode(String token, TypeReference<TokenBody<T>> tokenBodyTypeReference) {
        var result = new DecodeTokenResult<T>();

        try {
            var subject = this.jwtParser.parseClaimsJws(token).getBody().getSubject();
            var objectMapper = new ObjectMapper();

            var tokenBody = objectMapper.readValue(subject, tokenBodyTypeReference);
            result.isTokenValid = true;
            result.tokenBody = tokenBody;
        } catch (JsonProcessingException | MalformedJwtException | SignatureException | WeakKeyException | DecodingException | IllegalArgumentException e) {
            result.isTokenValid = false;
            result.decodeException = e;
        }

        return result;
    }
}
