package authentication;

import authentication.app.User;
import authentication.app.UserAccessTokenPayload;
import authentication.app.UserRefreshTokenPayload;
import authentication.jwt.dto.TokenBody;
import authentication.jwt.dto.TokenType;
import com.fasterxml.jackson.core.type.TypeReference;
import org.junit.Test;

import java.time.Instant;
import java.util.UUID;

import static org.junit.Assert.*;

public class LibraryTest {
    private final static TypeReference<TokenBody<UserAccessTokenPayload>> userAccessTokenPayloadReference = new TypeReference<>() {};
    private final static TypeReference<TokenBody<UserRefreshTokenPayload>> userRefreshTokenPayloadReference = new TypeReference<>() {};
    final private TestFactory testFactory = new TestFactory();

    @Test
    public void testTokenStorageService()
    {
        var tokenStorageService = this.testFactory.createTokenStorageService();

        assertFalse(tokenStorageService.isTokenInStorage("user", "123"));
        tokenStorageService.addTokenToStorage("user", "123");
        assertTrue(tokenStorageService.isTokenInStorage("user", "123"));
        tokenStorageService.removeTokenFromStorage("user", "123");
        assertFalse(tokenStorageService.isTokenInStorage("user", "123"));
    }

    @Test
    public void testIssueAccessToken()
    {
        var jwtService = this.testFactory.createJwtService();
        var authenticationTokenService = this.testFactory.createAuthenticationTokenService();

        var user = new User();
        user.id = UUID.fromString("7770b1b4-191c-11ee-be56-0242ac120002");
        user.email = "7770b1b4-191c-11ee-be56-0242ac120002@gmail.com";

        var token = authenticationTokenService.issueAccessToken("user", user);

        var decodeTokenResult = jwtService.decodeToken(token, LibraryTest.userAccessTokenPayloadReference);
        assertTrue(decodeTokenResult.isTokenValid);
        assertEquals(user.id.toString(), decodeTokenResult.tokenBody.id);
        assertEquals(TokenType.ACCESS_TOKEN, decodeTokenResult.tokenBody.tokenType);
        assertEquals(user.email, decodeTokenResult.tokenBody.payload.email);
        Long expectedTokenExpiresAt = (Instant.now().toEpochMilli() / 1000) + 60L;
        assertEquals(expectedTokenExpiresAt, decodeTokenResult.tokenBody.expiresAt);
    }

    @Test
    public void testIssueRefreshToken()
    {
        var user = new User();
        user.id = UUID.fromString("7770b1b4-191c-11ee-be56-0242ac120002");
        user.email = "7770b1b4-191c-11ee-be56-0242ac120002@gmail.com";

        var refreshTokenService = this.testFactory.createRefreshTokenService();
        var refreshToken = refreshTokenService.issueRefreshToken("user", user);

        var jwtService = this.testFactory.createJwtService();
        var decodeTokenResult = jwtService.decodeToken(refreshToken, LibraryTest.userRefreshTokenPayloadReference);

        assertTrue(decodeTokenResult.isTokenValid);
        assertEquals(user.id.toString(), decodeTokenResult.tokenBody.id);
        assertEquals(TokenType.REFRESH_TOKEN, decodeTokenResult.tokenBody.tokenType);
        assertEquals(user.id, decodeTokenResult.tokenBody.payload.id);
    }

    @Test
    public void testsContext()
    {
        var contextService = this.testFactory.createContextService();
        var context = contextService.getContextByName("user");
        assertEquals(context.getContextObjectClass(), User.class);

        var randomUUID = UUID.randomUUID();
        var user = (User) context.getContextObjectById(randomUUID.toString());
        assertEquals(randomUUID + "@gmail.com", user.email);
    }

    @Test
    public void testsTokenEncodeAndDecode() {
        var jwtService = this.testFactory.createJwtService();

        var tokenPayload = new UserAccessTokenPayload();
        tokenPayload.email = "lehadnk@gmail.com";

        var tokenBody = new TokenBody<UserAccessTokenPayload>();
        tokenBody.id = "1";
        tokenBody.context = "user";
        tokenBody.expiresAt = 1688153468L;
        tokenBody.payload = tokenPayload;
        var encodedToken = jwtService.encodeToken(tokenBody);

        var decodeTokenResult = jwtService.decodeToken(encodedToken, LibraryTest.userAccessTokenPayloadReference);
        assertTrue(decodeTokenResult.isTokenValid);
        assertNotNull(decodeTokenResult.tokenBody);
        assertNotNull(decodeTokenResult.tokenBody.payload);
        assertEquals("lehadnk@gmail.com", decodeTokenResult.tokenBody.payload.email);
    }
}
