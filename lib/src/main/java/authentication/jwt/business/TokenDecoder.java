package authentication.jwt.business;

import authentication.jwt.dto.DecodeTokenResult;
import authentication.jwt.dto.TokenBody;
import authentication.jwt.dto.TokenType;
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

    public DecodeTokenResult<T> decode(String token, Class<T> tokenPayloadClassReference) {
        var result = new DecodeTokenResult<T>();

        try {
            var jwsClaims = jwtParser.parseSignedClaims(token);

            var tokenBody = new TokenBody<T>();
            tokenBody.expiresAt = jwsClaims.getPayload().getExpiration();
            tokenBody.context = jwsClaims.getPayload().getAudience().stream().findFirst().orElseThrow();
            tokenBody.tokenType = jwsClaims.getPayload().get("tokenType", TokenType.class);
            tokenBody.id = jwsClaims.getPayload().getSubject();

            if (tokenPayloadClassReference != null) {
                var payload = jwsClaims.getPayload().get("payload", tokenPayloadClassReference);
                tokenBody.payload = payload;
            }

            result.isTokenValid = true;
            result.tokenBody = tokenBody;
        } catch (UnsupportedJwtException | MalformedJwtException | SignatureException | WeakKeyException | DecodingException | IllegalArgumentException | NullPointerException e) {
            result.isTokenValid = false;
            result.decodeException = e;
        } catch (ExpiredJwtException e) {
            result.isTokenValid = false;
            result.isTokenExpired = true;
            result.decodeException = e;
        }

        return result;
    }
}
