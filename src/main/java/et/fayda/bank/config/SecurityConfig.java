package et.fayda.bank.config;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Arrays;
import java.util.function.Consumer;

@Configuration
public class SecurityConfig {

    // eSignet authorize parameters, same as build_auth_url in the Django oidc-project (oidc_app/views.py).
    private static final String ACR_VALUES =
            "mosip:idp:acr:generated-code mosip:idp:acr:linked-wallet mosip:idp:acr:biometrics";
    private static final String CLAIMS = "{\"userinfo\":{\"name\":{\"essential\":true},"
            + "\"phone_number\":{\"essential\":true},\"email\":{\"essential\":true},"
            + "\"picture\":{\"essential\":true},\"gender\":{\"essential\":true},"
            + "\"birthdate\":{\"essential\":true},\"address\":{\"essential\":true},"
            + "\"nationality\":{\"essential\":true},\"individual_id\":{\"essential\":true}},"
            + "\"id_token\":{}}";

    private static Consumer<OAuth2AuthorizationRequest.Builder> faydaAuthorizeParameters() {
        return builder -> builder.additionalParameters(params -> {
            params.put("acr_values", ACR_VALUES);
            params.put("claims", CLAIMS);
            params.put("claims_locales", "en");
            params.put("display", "page");
            params.put("ui_locales", "en");
        });
    }

    private final OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;
    private final OAuth2UserService<OidcUserRequest, OidcUser> faydaUserService;

    public SecurityConfig(
            OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient,
            OAuth2UserService<OidcUserRequest, OidcUser> faydaUserService) {
        this.accessTokenResponseClient = accessTokenResponseClient;
        this.faydaUserService = faydaUserService;
    }

    /** What the callback request carried, to tell a lost session cookie from a state mismatch. */
    private static String callbackContext(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        Object saved = session == null ? null : session.getAttribute(
                HttpSessionOAuth2AuthorizationRequestRepository.class.getName() + ".AUTHORIZATION_REQUEST");
        String savedState = saved instanceof OAuth2AuthorizationRequest authRequest ? authRequest.getState() : null;
        Cookie[] cookies = request.getCookies();
        long sessionCookies = cookies == null ? 0
                : Arrays.stream(cookies).filter(c -> "JSESSIONID".equals(c.getName())).count();
        return "callback: " + request.getRequestURL() + (request.getQueryString() == null ? "" : "?" + request.getQueryString())
                + "\nhost=" + request.getHeader("Host")
                + "\nJSESSIONID cookies sent=" + sessionCookies
                + ", requested session=" + request.getRequestedSessionId()
                + ", valid=" + request.isRequestedSessionIdValid()
                + ", current session=" + (session == null ? "none" : session.getId())
                + "\nstate returned=" + request.getParameter("state")
                + "\nstate saved=" + savedState;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           ClientRegistrationRepository clientRegistrationRepository) throws Exception {
        DefaultOAuth2AuthorizationRequestResolver authorizationRequestResolver =
                new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository,
                        OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
        authorizationRequestResolver.setAuthorizationRequestCustomizer(FaydaNonce.authorizationRequestCustomizer()
                .andThen(OAuth2AuthorizationRequestCustomizers.withPkce())
                .andThen(faydaAuthorizeParameters()));

        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/css/**", "/images/**", "/coming-soon",
                                "/unverified-dashboard", "/error").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth -> oauth
                        .loginPage("/")
                        .authorizationEndpoint(authorization -> authorization
                                .authorizationRequestResolver(authorizationRequestResolver)
                        )
                        .defaultSuccessUrl("/welcome", true)
                        .redirectionEndpoint(redir -> redir
                                .baseUri("/callback")
                        )
                        .tokenEndpoint(token -> token
                                .accessTokenResponseClient(accessTokenResponseClient)
                        )
                        .userInfoEndpoint(userInfo -> userInfo
                                .oidcUserService(faydaUserService)
                        )
                        .failureHandler((request, response, exception) -> {
                            LoginError error = LoginError.from(exception).withContext(callbackContext(request));
                            System.out.println("========== OAUTH LOGIN FAILED ==========");
                            System.out.println(error.title() + ": " + error.message());
                            System.out.println(error.detail());
                            System.out.println("========================================");
                            exception.printStackTrace();
                            request.getSession().setAttribute(LoginError.SESSION_KEY, error);
                            response.sendRedirect("/?error");
                        })
                )
                // Protected page without a session (never signed in, expired, or app restarted): back to sign in with a notice.
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint((request, response, exception) -> response.sendRedirect("/?expired"))
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/")
                );
        return http.build();
    }
}