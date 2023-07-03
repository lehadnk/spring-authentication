package authentication.token_storage;

public class VoidTokenStorage implements TokenStorageInterface {
    @Override
    public void addTokenToStorage(String contextName, String token) {
    }

    @Override
    public boolean isTokenInStorage(String contextName, String token) {
        return true;
    }

    @Override
    public void removeTokenFromStorage(String contextName, String token) {
    }
}
