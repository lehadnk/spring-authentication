package authentication.validation;

import authentication.jwt.dto.DecodeTokenResult;
import authentication.token_storage.TokenStorageService;

import java.sql.Date;
import java.time.Instant;

public class ValidationService {
    private final TokenStorageService tokenStorageService;

    public ValidationService(
            TokenStorageService tokenStorageService
    ) {
        this.tokenStorageService = tokenStorageService;
    }

    public <T> void validateToken(String encodedToken, DecodeTokenResult<T> decodeTokenResult)
    {
        if (decodeTokenResult.tokenBody == null) {
            decodeTokenResult.isTokenValid = false;
            return;
        }
        if (!tokenStorageService.isTokenInStorage(decodeTokenResult.tokenBody.context, encodedToken)) {
            decodeTokenResult.isTokenValid = false;
        }
    }
}
