package authentication.jwt;

import authentication.jwt.business.TokenDecoder;
import authentication.jwt.business.TokenEncoder;
import authentication.jwt.dto.DecodeTokenResult;
import authentication.jwt.dto.TokenBody;
import com.fasterxml.jackson.core.type.TypeReference;

public class JwtService {
    private final JwtFactory jwtFactory;

    public JwtService(
            JwtFactory jwtFactory
    ) {
        this.jwtFactory = jwtFactory;
    }

    public <T> String encodeToken(TokenBody<T> tokenBody)
    {
        TokenEncoder<T> tokenEncoder = this.jwtFactory.createTokenEncoder();
        return tokenEncoder.encodeToken(tokenBody);
    }

    public <T> DecodeTokenResult<T> decodeToken(String token, TypeReference<TokenBody<T>> tokenBodyTypeReference)
    {
        TokenDecoder<T> tokenDecoder = this.jwtFactory.createTokenDecoder();
        return tokenDecoder.decode(token, tokenBodyTypeReference);
    }
}
