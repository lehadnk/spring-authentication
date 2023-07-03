package authentication.validation;

import authentication.jwt.dto.DecodeTokenResult;
import authentication.token_storage.TokenStorageService;

import java.time.Instant;

public class ValidationService {
    private final TokenStorageService tokenStorageService;

    public ValidationService(
            TokenStorageService tokenStorageService
    )
    {
        this.tokenStorageService = tokenStorageService;
    }

    public <T> void validateToken(String encodedToken, DecodeTokenResult<T> decodeTokenResult)
    {
        if (decodeTokenResult.tokenBody == null) {
            decodeTokenResult.isTokenValid = false;
            return;
        }
        if (Instant.ofEpochSecond(decodeTokenResult.tokenBody.expiresAt).isBefore(Instant.now())) {
            decodeTokenResult.isTokenValid = false;
        }
        if (tokenStorageService.isTokenInStorage(decodeTokenResult.tokenBody.context, encodedToken)) {
            decodeTokenResult.isTokenValid = false;
        }
    }
}