package authentication.app;

import authentication.context.AuthorizationContextProviderInterface;

import java.util.UUID;

public class UserAuthorizationContext implements AuthorizationContextProviderInterface<User, UserAccessTokenPayload, UserRefreshTokenPayload> {
    @Override
    public Class<User> getContextObjectClass() {
        return User.class;
    }

    @Override
    public String getContextObjectId(User user) {
        return user.id.toString();
    }

    @Override
    public Class<UserAccessTokenPayload> getAccessTokenPayloadClass() {
        return UserAccessTokenPayload.class;
    }

    @Override
    public Class<UserRefreshTokenPayload> getRefreshTokenPayloadClass() {
        return UserRefreshTokenPayload.class;
    }

    @Override
    public String getContextName() {
        return "user";
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

    @Override
    public UserAccessTokenPayload serializeAccessTokenPayload(User user)
    {
        var payload = new UserAccessTokenPayload();
        payload.email = user.email;
        return payload;
    }

    @Override
    public UserRefreshTokenPayload serializeRefreshTokenPayload(User user)
    {
        var payload = new UserRefreshTokenPayload();
        payload.id = user.id;
        return payload;
    }
}
