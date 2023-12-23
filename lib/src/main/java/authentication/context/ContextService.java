package authentication.context;

import authentication.context.exceptions.AuthorizationContextInitializationException;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ContextService {
    private final Map<String, AuthorizationContextProviderInterface> contextProviders = new HashMap<>();

    public ContextService(
            List<AuthorizationContextProviderInterface<?, ?, ?>> contextProviders
    ) throws AuthorizationContextInitializationException {
        for (var contextProvider : contextProviders) {
            if (this.contextProviders.containsKey(contextProvider.getContextName())) {
                throw new AuthorizationContextInitializationException();
            }

            this.contextProviders.put(contextProvider.getContextName(), contextProvider);
        }
    }

    public <TContextObject, TAccessTokenPayloadObject, TRefreshTokenPayloadObject> AuthorizationContextProviderInterface<TContextObject, TAccessTokenPayloadObject, TRefreshTokenPayloadObject> getContextByName(String name)
    {
        return this.contextProviders.get(name);
    }
}
