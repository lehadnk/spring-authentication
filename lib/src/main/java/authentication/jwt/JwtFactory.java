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
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
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
                jwtSecret.getBytes(StandardCharsets.UTF_8),
                SignatureAlgorithm.HS256.getJcaName()
        );
    }

    protected JwtBuilder createJwtBuilder() {

        return Jwts.builder().signWith(this.createSecretKeySpec(this.jwtSecret));
    }

    protected <T> JwtParser createJwtParser(Class<T> tokenPayloadClassReference)
    {
        var payloadObjectMap = new HashMap<String, Object>();
        if (tokenPayloadClassReference != null) {
            payloadObjectMap.put("payload", tokenPayloadClassReference);
        }
        payloadObjectMap.put("tokenType", TokenType.class);

        return Jwts.parser()
                .verifyWith(this.createSecretKeySpec(this.jwtSecret))
                .json(new JacksonDeserializer(payloadObjectMap))
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
        return new TokenDecoder<T>(
                this.createJwtParser(tokenPayloadClassReference)
        );
    }
}
