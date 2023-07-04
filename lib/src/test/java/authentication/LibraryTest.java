package authentication;

import authentication.access_token.dto.ValidateAccessTokenResult;
import authentication.app.User;
import authentication.app.UserAccessTokenPayload;
import authentication.app.UserAuthorizationContext;
import authentication.app.UserRefreshTokenPayload;
import authentication.context.AuthorizationContextProviderInterface;
import authentication.context.ContextService;
import authentication.context.exceptions.AuthorizationContextInitializationException;
import authentication.jwt.dto.TokenBody;
import authentication.jwt.dto.TokenType;
import com.fasterxml.jackson.core.type.TypeReference;
import org.junit.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.UUID;

import static org.junit.Assert.*;

public class LibraryTest {
    private final static TypeReference<TokenBody<UserAccessTokenPayload>> userAccessTokenPayloadReference = new TypeReference<>() {};
    private final static TypeReference<TokenBody<UserRefreshTokenPayload>> userRefreshTokenPayloadReference = new TypeReference<>() {};
    final private TestFactory testFactory = new TestFactory();

    @Test
    public void testExchangeIncorrectRefreshToken()
    {
        var incorrectToken = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ7XCJjb250ZXh0XCI6XCJ1c2VyXCIsXCJpZFwiOlwiNzc3MGIxYjQtMTkxYy0xMWVlLWJlNTYtMDI0MmFjMTIwMDAyXCIsXCJ0b2tlblR5cGVcIjpcIlJFRlJFU0hfVE9LRU5cIixcImV4cGlyZXNBdFwiOjE2ODg0MDUzNTUsXCJwYXlsb2FkXCI6e1wiaWRcIjpcIjc3NzBiMWI0LTE5MWMtMTFlZS1iZTU2LTAyNDJhYzEyMDAwMlwifX0ifQ.cpLC-DEH3dgZeqPsL6PeWaa2gQi-yAmHK8JjSLLEmaM";
        var refreshTokenService = this.testFactory.createRefreshTokenService();
        var tokenExchangeResponse = refreshTokenService.exchangeRefreshTokenForAuthorizationToken("user", incorrectToken, LibraryTest.userRefreshTokenPayloadReference);

        assertFalse(tokenExchangeResponse.isSuccess);
        assertNull(tokenExchangeResponse.accessToken);
    }

    @Test
    public void testExchangeRefreshTokenForAuthorizationToken()
    {
        var refreshTokenService = this.testFactory.createRefreshTokenService();

        var user = new User();
        user.id = UUID.fromString("7770b1b4-191c-11ee-be56-0242ac120002");
        user.email = "7770b1b4-191c-11ee-be56-0242ac120002@gmail.com";

        var refreshToken = refreshTokenService.issueRefreshToken("user", user);
        var tokenExchangeResponse = refreshTokenService.exchangeRefreshTokenForAuthorizationToken("user", refreshToken, LibraryTest.userRefreshTokenPayloadReference);
        assertTrue(tokenExchangeResponse.isSuccess);

        var jwtService = this.testFactory.createJwtService();
        var decodeTokenResult = jwtService.decodeToken(tokenExchangeResponse.accessToken, LibraryTest.userAccessTokenPayloadReference);
        assertTrue(decodeTokenResult.isTokenValid);
        assertEquals(user.id.toString(), decodeTokenResult.tokenBody.id);
    }

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
        var authenticationTokenService = this.testFactory.createAccessTokenService();

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
    public void testsGetContext()
    {
        var contextService = this.testFactory.createContextService();
        var context = contextService.getContextByName("user");
        assertEquals(context.getContextObjectClass(), User.class);

        var randomUUID = UUID.randomUUID();
        var user = (User) context.getContextObjectById(randomUUID.toString());
        assertEquals(randomUUID + "@gmail.com", user.email);
    }

    @Test
    public void testGetAbsentContext()
    {
        var contextProvidersList = new ArrayList<AuthorizationContextProviderInterface<?, ?, ?>>(1);
        contextProvidersList.add(new UserAuthorizationContext());
        contextProvidersList.add(new UserAuthorizationContext());
        assertThrows(AuthorizationContextInitializationException.class, () -> new ContextService(contextProvidersList));

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

    @Test
    public void testDecodeMalformedToken()
    {
        var authenticationService = this.testFactory.createAccessTokenService();
    }

    @Test
    public void testValidateAccessToken()
    {
        var user = new User();
        user.id = UUID.fromString("7770b1b4-191c-11ee-be56-0242ac120002");
        user.email = "7770b1b4-191c-11ee-be56-0242ac120002@gmail.com";

        var accessTokenService = this.testFactory.createAccessTokenService();
        var accessToken = accessTokenService.issueAccessToken("user", user);

        ValidateAccessTokenResult<User> validateAccessTokenResult = accessTokenService.validateAuthenticationToken("user", accessToken, LibraryTest.userAccessTokenPayloadReference);
        assertTrue(validateAccessTokenResult.isValid);
        assertEquals(user.id, validateAccessTokenResult.contextObject.id);
    }

    @Test
    public void testDecodeIncorrectToken()
    {
        var accessTokenService = this.testFactory.createAccessTokenService();
        var validateAccessTokenResult = accessTokenService.validateAuthenticationToken("user", "qwe123", LibraryTest.userAccessTokenPayloadReference);
        assertFalse(validateAccessTokenResult.isValid);
        assertNull(validateAccessTokenResult.contextObject);
    }
}
