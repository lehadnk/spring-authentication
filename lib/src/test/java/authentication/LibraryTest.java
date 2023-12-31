package authentication;

import authentication.access_token.dto.ValidateAccessTokenResult;
import authentication.app.User;
import authentication.app.UserAccessTokenPayload;
import authentication.app.UserAuthorizationContextProvider;
import authentication.app.UserNoPayloadAuthorizationContextProvider;
import authentication.context.AuthorizationContextProviderInterface;
import authentication.context.ContextService;
import authentication.context.exceptions.AuthorizationContextInitializationException;
import authentication.jwt.JwtFactory;
import authentication.jwt.JwtService;
import authentication.jwt.dto.TokenBody;
import authentication.jwt.dto.TokenType;
import org.junit.Test;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.UUID;

import static org.junit.Assert.*;

public class LibraryTest {
    final private TestFactory testFactory = new TestFactory();

    @Test
    public void testExchangeIncorrectRefreshToken()
    {
        var incorrectToken = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ7XCJjb250ZXh0XCI6XCJ1c2VyXCIsXCJpZFwiOlwiNzc3MGIxYjQtMTkxYy0xMWVlLWJlNTYtMDI0MmFjMTIwMDAyXCIsXCJ0b2tlblR5cGVcIjpcIlJFRlJFU0hfVE9LRU5cIixcImV4cGlyZXNBdFwiOjE2ODg0MDUzNTUsXCJwYXlsb2FkXCI6e1wiaWRcIjpcIjc3NzBiMWI0LTE5MWMtMTFlZS1iZTU2LTAyNDJhYzEyMDAwMlwifX0ifQ.cpLC-DEH3dgZeqPsL6PeWaa2gQi-yAmHK8JjSLLEmaM";
        var refreshTokenService = this.testFactory.createRefreshTokenService();
        var tokenExchangeResponse = refreshTokenService.exchangeRefreshTokenForAuthorizationToken("user", incorrectToken);

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
        var tokenExchangeResponse = refreshTokenService.exchangeRefreshTokenForAuthorizationToken("user", refreshToken);
        assertTrue(tokenExchangeResponse.isSuccess);

        var jwtService = this.testFactory.createJwtService();
        var decodeTokenResult = jwtService.decodeToken(tokenExchangeResponse.accessToken, new UserAuthorizationContextProvider().getAccessTokenPayloadClass());
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

        var decodeTokenResult = jwtService.decodeToken(token, new UserAuthorizationContextProvider().getAccessTokenPayloadClass());
        assertTrue(decodeTokenResult.isTokenValid);
        assertEquals(user.id.toString(), decodeTokenResult.tokenBody.id);
        assertEquals(TokenType.ACCESS_TOKEN, decodeTokenResult.tokenBody.tokenType);
        assertEquals(user.email, decodeTokenResult.tokenBody.payload.email);
        var expectedTokenExpiresAt = Date.from(Instant.now().plus(60, ChronoUnit.SECONDS));
        assertEquals(expectedTokenExpiresAt.toString(), decodeTokenResult.tokenBody.expiresAt.toString());
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
        var decodeTokenResult = jwtService.decodeToken(refreshToken, new UserAuthorizationContextProvider().getRefreshTokenPayloadClass());

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
        contextProvidersList.add(new UserAuthorizationContextProvider());
        contextProvidersList.add(new UserAuthorizationContextProvider());
        assertThrows(AuthorizationContextInitializationException.class, () -> new ContextService(contextProvidersList));

    }

    @Test
    public void testsTokenEncodeAndDecode() throws ParseException {
        var jwtService = this.testFactory.createJwtService();

        var tokenPayload = new UserAccessTokenPayload();
        tokenPayload.email = "lehadnk@gmail.com";

        var tokenBody = new TokenBody<UserAccessTokenPayload>();
        tokenBody.id = "1";
        tokenBody.context = "user";

        var formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
        tokenBody.expiresAt = formatter.parse("2024-04-30T10:00:00.000+0000");
        tokenBody.payload = tokenPayload;
        var encodedToken = jwtService.encodeToken(tokenBody);

        var decodeTokenResult = jwtService.decodeToken(encodedToken, new UserAuthorizationContextProvider().getAccessTokenPayloadClass());
        assertTrue(decodeTokenResult.isTokenValid);
        assertNotNull(decodeTokenResult.tokenBody);
        assertNotNull(decodeTokenResult.tokenBody.payload);
        assertEquals("lehadnk@gmail.com", decodeTokenResult.tokenBody.payload.email);
    }

    @Test
    public void testValidateAccessToken()
    {
        var user = new User();
        user.id = UUID.fromString("7770b1b4-191c-11ee-be56-0242ac120002");
        user.email = "7770b1b4-191c-11ee-be56-0242ac120002@gmail.com";

        var accessTokenService = this.testFactory.createAccessTokenService();
        var accessToken = accessTokenService.issueAccessToken("user", user);

        ValidateAccessTokenResult<User, UserAccessTokenPayload> validateAccessTokenResult = accessTokenService.validateAccessToken("user", accessToken);
        assertTrue(validateAccessTokenResult.isValid);
        assertEquals(user.id, validateAccessTokenResult.contextObject.id);
        assertEquals(user.email, validateAccessTokenResult.tokenPayload.email);
    }

    @Test
    public void testDecodeIncorrectToken()
    {
        var accessTokenService = this.testFactory.createAccessTokenService();
        var validateAccessTokenResult = accessTokenService.validateAccessToken("user", "qwe123");
        assertFalse(validateAccessTokenResult.isValid);
        assertNull(validateAccessTokenResult.contextObject);
    }

    @Test
    public void testDecodeMalformedToken()
    {
        var jwtService = this.testFactory.createJwtService();
        var tokenDecodeResult = jwtService.decodeToken("Bearer qwe", new UserAuthorizationContextProvider().getAccessTokenPayloadClass());
        assertFalse(tokenDecodeResult.isTokenValid);
    }

    @Test
    public void testDecodeTokenSignedWithIncorrectKey() throws ParseException {
        var jwtFactory1 = new JwtFactory("testtesttesttesttesttesttesttesttesttesttesttest");
        var jwtService1 = new JwtService(jwtFactory1);

        var tokenBody = new TokenBody<UserAccessTokenPayload>();
        tokenBody.id = "1";
        tokenBody.context = "user";

        var formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
        tokenBody.expiresAt = formatter.parse("2024-04-30T10:00:00.000+0000");

        var tokenGeneratedByService1 = jwtService1.encodeToken(tokenBody);

        var jwtFactory2 = new JwtFactory("qweqweqweqweqweqweqweqweqweqweqweqweqweqweqweqwe");
        var jwtService2 = new JwtService(jwtFactory2);

        var tokenDecodeResult = jwtService2.decodeToken(tokenGeneratedByService1, new UserAuthorizationContextProvider().getAccessTokenPayloadClass());
        assertFalse(tokenDecodeResult.isTokenValid);
    }

    @Test
    public void testDecodeExpiredToken() throws ParseException {
        var jwtService = this.testFactory.createJwtService();

        var tokenPayload = new UserAccessTokenPayload();
        tokenPayload.email = "lehadnk@gmail.com";

        var tokenBody = new TokenBody<UserAccessTokenPayload>();
        tokenBody.id = "1";
        tokenBody.context = "user";

        var formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
        tokenBody.expiresAt = formatter.parse("2020-04-30T10:00:00.000+0000");
        tokenBody.payload = tokenPayload;
        var encodedToken = jwtService.encodeToken(tokenBody);

        var decodeTokenResult = jwtService.decodeToken(encodedToken, new UserAuthorizationContextProvider().getAccessTokenPayloadClass());
        assertFalse(decodeTokenResult.isTokenValid);
    }

    @Test
    public void testNoPayloadAuthorizationContextProvider()
    {
        var jwtService = this.testFactory.createJwtService();
        var authenticationTokenService = this.testFactory.createAccessTokenService();

        var user = new User();
        user.id = UUID.fromString("7770b1b4-191c-11ee-be56-0242ac120002");
        user.email = "7770b1b4-191c-11ee-be56-0242ac120002@gmail.com";

        var token = authenticationTokenService.issueAccessToken("user-no-payload", user);

        var decodeTokenResult = jwtService.decodeToken(token, new UserNoPayloadAuthorizationContextProvider().getAccessTokenPayloadClass());
        assertTrue(decodeTokenResult.isTokenValid);
        assertEquals(user.id.toString(), decodeTokenResult.tokenBody.id);
        assertEquals(TokenType.ACCESS_TOKEN, decodeTokenResult.tokenBody.tokenType);
        assertNull(decodeTokenResult.tokenBody.payload);
        var expectedTokenExpiresAt = Date.from(Instant.now().plus(60, ChronoUnit.SECONDS));
        assertEquals(expectedTokenExpiresAt.toString(), decodeTokenResult.tokenBody.expiresAt.toString());
    }
}
