package authentication.token_storage;

public class TokenStorageService {
    private final TokenStorageInterface tokenStorage;

    public TokenStorageService(
            TokenStorageInterface tokenStorage
    ) {
        this.tokenStorage = tokenStorage;
    }

    public void addTokenToStorage(String contextName, String token)
    {
        this.tokenStorage.addTokenToStorage(contextName, token);
    }

    public boolean isTokenInStorage(String contextName, String token)
    {
        return this.tokenStorage.isTokenInStorage(contextName, token);
    }

    public void removeTokenFromStorage(String contextName, String token)
    {
        this.tokenStorage.removeTokenFromStorage(contextName, token);
    }
}
