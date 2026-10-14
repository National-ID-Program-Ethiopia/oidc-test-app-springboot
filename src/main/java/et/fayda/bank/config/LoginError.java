package et.fayda.bank.config;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

import java.io.Serializable;
import java.util.Map;

/**
 * A failed Fayda login, shown on the home page: a short title and message, an optional fix hint,
 * and the full diagnostic (error code, description and cause chain) in {@code detail}.
 * Same shape as the oidc-test-app server's error responses (utils/appError.js).
 */
public record LoginError(String title, String message, String hint, String detail) implements Serializable {

    public static final String SESSION_KEY = "FAYDA_LOGIN_ERROR";

    private static final String START_OVER =
            "Start a new login from the Sign In page. Refreshing the callback page reuses the old code.";

    // MOSIP IDA KYC-exchange codes that eSignet passes through as error_description.
    private static final Map<String, String[]> IDA_ERRORS = Map.of(
            "IDA-KYE-001", new String[]{"The identity provider has no record of this login.", START_OVER},
            "IDA-KYE-002", new String[]{"This login expired before it was completed.", START_OVER},
            "IDA-KYE-003", new String[]{"This login was already completed; an authorization code can be used only once.", START_OVER},
            "IDA-KYE-004", new String[]{"The login belongs to a different OIDC client.", "Check that CLIENT_ID in .env is the client registered with eSignet."},
            "IDA-KYE-006", new String[]{"No partner policy is configured for this client.", "Ask the eSignet/IDA admin to map a KYC exchange policy to the partner."}
    );

    /** Appends request context (callback params, session/cookie state) to the technical details. */
    public LoginError withContext(String context) {
        return new LoginError(title, message, hint, detail + "\n\n" + context);
    }

    public static LoginError from(AuthenticationException exception) {
        String code = null;
        String description = null;
        if (exception instanceof OAuth2AuthenticationException oae) {
            OAuth2Error error = oae.getError();
            code = error.getErrorCode();
            description = error.getDescription();
        }
        String message = description != null && !description.isBlank() ? description
                : code != null ? "The identity provider login failed with error code \"" + code + "\"."
                : exception.getMessage();
        String detail = diagnostic(code, exception);

        if (description != null) {
            for (Map.Entry<String, String[]> ida : IDA_ERRORS.entrySet()) {
                if (description.contains(ida.getKey())) {
                    return new LoginError("Sign-in could not be completed", ida.getValue()[0], ida.getValue()[1], detail);
                }
            }
        }
        if (description != null && description.contains("I/O error")) {
            // Spring's token/JWKS clients report network failures this way.
            return new LoginError("Could not reach eSignet", message,
                    "Check your network/VPN and the FAYDA_*_URI values in .env.", detail);
        }
        if (code == null) {
            return new LoginError("Sign-in failed", message, null, detail);
        }
        return switch (code) {
            case "invalid_nonce" -> new LoginError("Login session mismatch", message,
                    "Start the login from this browser tab and finish it without switching tabs or restarting the app.", detail);
            case "invalid_id_token" -> new LoginError("ID token rejected", message,
                    "Check FAYDA_JWK_SET_URI and CLIENT_ID in .env, and that this machine's clock is in sync.", detail);
            case "invalid_grant" -> new LoginError("Sign-in could not be completed", message, START_OVER, detail);
            case "invalid_client" -> new LoginError("Client authentication failed", message,
                    "Check that PRIVATE_KEY in .env matches the public key registered for CLIENT_ID in eSignet.", detail);
            case "invalid_token_response" -> new LoginError("Token exchange failed", message,
                    "Check FAYDA_TOKEN_URI and PRIVATE_KEY in .env.", detail);
            case "authorization_request_not_found" -> new LoginError("Login session not found", message,
                    "The app was restarted or the session expired during login. " + START_OVER, detail);
            case "userinfo_decrypt_failed" -> new LoginError("Userinfo decryption failed", message,
                    "Update the eSignet client encPublicKey to the public JWK of PRIVATE_KEY_USER_INFO, then sign in again.", detail);
            case "userinfo_error" -> new LoginError("Could not load your profile", message, null, detail);
            case "idp_unreachable" -> new LoginError("Could not reach eSignet", message,
                    "Check your network/VPN and FAYDA_USER_INFO_URI in .env, then sign in again.", detail);
            case "access_denied" -> new LoginError("Sign-in cancelled", message, null, detail);
            default -> new LoginError("Sign-in failed", message, null, detail);
        };
    }

    private static String diagnostic(String code, Throwable exception) {
        StringBuilder detail = new StringBuilder();
        if (code != null) {
            detail.append("error=").append(code).append('\n');
        }
        for (Throwable t = exception; t != null; t = t.getCause()) {
            detail.append(t == exception ? "" : "caused by: ")
                    .append(t.getClass().getName()).append(": ").append(t.getMessage()).append('\n');
            if (t.getCause() == t) {
                break;
            }
        }
        return detail.toString().trim();
    }
}
