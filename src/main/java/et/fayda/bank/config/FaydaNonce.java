package et.fayda.bank.config;

import jakarta.servlet.http.HttpSession;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.function.Consumer;

/**
 * Per-login nonce sent to eSignet as a raw numeric value (Java long compatible),
 * instead of Spring's default SHA-256 hash of a random string.
 */
public final class FaydaNonce {

    static final String SESSION_KEY = "FAYDA_OIDC_NONCE";
    private static final SecureRandom RANDOM = new SecureRandom();

    private FaydaNonce() {
    }

    /** URL-safe, unpadded state, so it survives the eSignet round trip unchanged (Spring's default ends in '='). */
    static String generateState() {
        byte[] bytes = new byte[24];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    static String generate() {
        return Long.toString(RANDOM.nextLong(1, Long.MAX_VALUE));
    }

    static Consumer<OAuth2AuthorizationRequest.Builder> authorizationRequestCustomizer() {
        return builder -> {
            String nonce = generate();
            currentSession(true).setAttribute(SESSION_KEY, nonce);
            // Removing the attribute turns off Spring's hashed-nonce check;
            // the raw nonce is validated in FaydaUserService instead.
            builder.state(generateState())
                    .attributes(attrs -> attrs.remove(OidcParameterNames.NONCE))
                    .additionalParameters(params -> params.put(OidcParameterNames.NONCE, nonce));
        };
    }

    /** Returns the nonce issued for this session's login and clears it so it cannot be replayed. */
    static String consume() {
        HttpSession session = currentSession(false);
        if (session == null) {
            return null;
        }
        String nonce = (String) session.getAttribute(SESSION_KEY);
        session.removeAttribute(SESSION_KEY);
        return nonce;
    }

    private static HttpSession currentSession(boolean create) {
        ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attrs == null) {
            throw new IllegalStateException("No current HTTP request to hold the OIDC nonce");
        }
        return attrs.getRequest().getSession(create);
    }
}
