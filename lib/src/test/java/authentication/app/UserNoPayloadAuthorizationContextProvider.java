package authentication.app;

import authentication.context.AuthorizationContextProviderInterface;

import java.util.UUID;

public class UserNoPayloadAuthorizationContextProvider implements AuthorizationContextProviderInterface<User, Void, Void> {
    @Override
    public Class<User> getContextObjectClass() {
        return User.class;
    }

    @Override
    public String getContextObjectId(User user) {
        return user.id.toString();
    }

    @Override
    public String getContextName() {
        return "user-no-payload";
    }

    @Override
    public User getContextObjectById(String id) {
        var user = new User();
        user.id = UUID.fromString(id);
        user.email = user.id + "@gmail.com";
        return user;
    }

    @Override
    public Long getAccessTokenExpirationTime() {
        return 60L;
    }

    @Override
    public Long getRefreshTokenExpirationTime() {
        return 120L;
    }
}
