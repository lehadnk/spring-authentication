package authentication.jwt;

import authentication.jwt.business.TokenDecoder;
import authentication.jwt.business.TokenEncoder;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

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

    protected JwtParser createJwtParser()
    {
        return Jwts.parserBuilder().setSigningKey(this.createSecretKeySpec(this.jwtSecret)).build();
    }

    public <T> TokenEncoder<T> createTokenEncoder()
    {
        return new TokenEncoder<>(
                this.createJwtBuilder()
        );
    }

    public <T>TokenDecoder<T> createTokenDecoder()
    {
        return new TokenDecoder<>(
                this.createJwtParser()
        );
    }
}
