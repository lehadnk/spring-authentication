package authentication.token_storage;

import java.util.HashMap;
import java.util.Map;

public class InMemoryTokenStorage implements TokenStorageInterface {
    private Map<String, Boolean> tokens = new HashMap<>();

    @Override
    public void addTokenToStorage(String contextName, String token) {
        this.tokens.put(this.getKey(contextName, token), true);
    }

    @Override
    public boolean isTokenInStorage(String contextName, String token) {
        return this.tokens.containsKey(this.getKey(contextName, token));
    }

    @Override
    public void removeTokenFromStorage(String contextName, String token) {
        this.tokens.remove(this.getKey(contextName, token));
    }

    private String getKey(String contextName, String token)
    {
        return contextName + ":" + token;
    }
}
