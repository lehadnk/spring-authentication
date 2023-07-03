package authentication.token_storage;

public interface TokenStorageInterface {
    void addTokenToStorage(String contextName, String token);
    boolean isTokenInStorage(String contextName, String token);
    void removeTokenFromStorage(String contextName, String token);
}
