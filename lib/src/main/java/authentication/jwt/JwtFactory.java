package authentication.jwt;

import authentication.jwt.business.TokenDecoder;
import authentication.jwt.business.TokenEncoder;
import authentication.jwt.dto.TokenType;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.jackson.io.JacksonDeserializer;

import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Map;

public class JwtFactory {
    private final String jwtSecret;

    public JwtFactory(
        String jwtSecret
    ) {
        this.jwtSecret = jwtSecret;
    }

    protected SecretKeySpec createSecretKeySpec(String jwtSecret)
    {
        return new SecretKeySpec(
                Base64.getDecoder().decode(jwtSecret),
                SignatureAlgorithm.HS256.getJcaName()
        );
    }

    protected JwtBuilder createJwtBuilder() {

        return Jwts.builder().signWith(this.createSecretKeySpec(this.jwtSecret));
    }

    protected <T> JwtParser createJwtParser(Class<T> tokenPayloadClassReference)
    {
        return Jwts.parser()
                .verifyWith(this.createSecretKeySpec(this.jwtSecret))
                .json(new JacksonDeserializer(Map.of(
                        "payload", tokenPayloadClassReference,
                        "tokenType", TokenType.class
                )))
                .build();
    }

    public <T> TokenEncoder<T> createTokenEncoder()
    {
        return new TokenEncoder<>(
                this.createJwtBuilder()
        );
    }

    public <T> TokenDecoder<T> createTokenDecoder(Class<T> tokenPayloadClassReference)
    {
        return new TokenDecoder<>(
                this.createJwtParser(tokenPayloadClassReference)
        );
    }
}
