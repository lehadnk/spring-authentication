# Define authorization context

```java
@RequiredArgsConstructor
public class UserAuthorizationContextProvider implements AuthorizationContextProviderInterface<User, Empty, Empty> {
    private final UserClient userClient;

    @Override
    public String getContextName() {
        return "user";
    }

    @Override
    public Class<User> getContextObjectClass() {
        return User.class;
    }

    @Override
    public String getContextObjectId(User user) {
        return user.uuid.toString();
    }

    @Override
    public User getContextObjectById(String s) {
        return this.userClient.getUserByUuid(new UuidRequest(UUID.fromString(s)));
    }

    @Override
    public Long getAccessTokenExpirationTime() {
        return 86400L; // 1 day
    }

    @Override
    public Long getRefreshTokenExpirationTime() {
        return 31536000L; // 1 year
    }
}
```

```java
import authentication.token_storage.TokenStorageInterface;
import authentication.token_storage.VoidTokenStorage;
import org.springframework.context.annotation.Bean;

@Configuration
@Import({
    AccessTokenBeanConfiguration.class,
    ContextBeanConfiguration.class,
    JwtBeanConfiguration.class,
    RefreshTokenBeanConfiguration.class,
    TokenStorageBeanConfiguration.class,
    ValidationBeanConfiguration.class
})
public class AuthorizationBeanConfiguration {
    @Bean
    public TokenStorageInterface createTokenStorage() {
        return new VoidTokenStorage();
    }
}
```

```yml
authentication:
    jwt:
        secret: secrety-secret
```

# Publishing to remote repository
`./gradlew clean sonatypeCentralUpload`