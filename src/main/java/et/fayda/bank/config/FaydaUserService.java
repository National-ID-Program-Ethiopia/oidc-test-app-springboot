package et.fayda.bank.config;

import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;

import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.Map;

@Component
public class FaydaUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    private static final Duration TIMEOUT = Duration.ofSeconds(20);

    private final HttpClient httpClient = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();
    private final UserInfoDecoder userInfoDecoder;

    public FaydaUserService(UserInfoDecoder userInfoDecoder) {
        this.userInfoDecoder = userInfoDecoder;
    }

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        validateNonce(userRequest);

        String userInfoUri = userRequest.getClientRegistration()
                .getProviderDetails().getUserInfoEndpoint().getUri();
        String accessToken = userRequest.getAccessToken().getTokenValue();

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(userInfoUri))
                    .timeout(TIMEOUT)
                    .header("Authorization", "Bearer " + accessToken)
                    .GET()
                    .build();

            HttpResponse<String> response =
                    httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                String description = "Userinfo endpoint returned HTTP " + response.statusCode() + ": " + response.body();
                throw new OAuth2AuthenticationException(new OAuth2Error("userinfo_error", description, null), description);
            }

            Map<String, Object> claims = userInfoDecoder.decode(response.body());

            OidcUserInfo userInfo = new OidcUserInfo(claims);

            return new DefaultOidcUser(
                    null,
                    userRequest.getIdToken(),
                    userInfo,
                    "sub"
            );

        } catch (OAuth2AuthenticationException e) {
            throw e;
        } catch (HttpTimeoutException e) {
            throw unreachable("Userinfo endpoint " + userInfoUri + " did not respond within " + TIMEOUT.toSeconds() + "s", e);
        } catch (ConnectException e) {
            throw unreachable("Could not connect to userinfo endpoint " + userInfoUri, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw unreachable("Userinfo request was interrupted", e);
        } catch (Exception e) {
            String description = "Failed to load Fayda userinfo: " + e.getMessage();
            throw new OAuth2AuthenticationException(new OAuth2Error("userinfo_error", description, null), description, e);
        }
    }

    private static OAuth2AuthenticationException unreachable(String description, Exception cause) {
        return new OAuth2AuthenticationException(new OAuth2Error("idp_unreachable", description, null), description, cause);
    }

    private void validateNonce(OidcUserRequest userRequest) {
        String expected = FaydaNonce.consume();
        String actual = userRequest.getIdToken().getNonce();
        if (expected == null || !expected.equals(actual)) {
            System.out.println("Nonce mismatch: expected=" + expected + " id_token=" + actual);
            String description = "Nonce mismatch: expected " + expected + ", id_token has " + actual;
            throw new OAuth2AuthenticationException(new OAuth2Error("invalid_nonce", description, null), description);
        }
    }
}
