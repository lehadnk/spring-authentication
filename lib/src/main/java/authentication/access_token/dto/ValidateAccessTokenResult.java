package authentication.access_token.dto;

public class ValidateAccessTokenResult<T> {
    public Boolean isValid;
    public T contextObject;
}
