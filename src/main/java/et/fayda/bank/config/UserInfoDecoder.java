package et.fayda.bank.config;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

/**
 * Handles both eSignet userinfo formats:
 * - JWS (3 compact parts): signed JWT claims
 * - JWE (5 compact parts): encrypted nested JWT, then signed JWT claims
 * - JSON object
 */
@Component
public class UserInfoDecoder {

    private final String encryptionKey;

    public UserInfoDecoder(
            @Value("${PRIVATE_KEY_USER_INFO:}") String privateKeyUserInfo,
            @Value("${PRIVATE_KEY}") String privateKey) {
        // Encryption private JWK used to decrypt JWE userinfo (client additionalConfig.userinfo_response_type=JWE).
        // Falls back to PRIVATE_KEY if a dedicated enc key is not set.
        this.encryptionKey = StringUtils.hasText(privateKeyUserInfo) ? privateKeyUserInfo : privateKey;
    }

    public Map<String, Object> decode(String rawUserinfo) throws Exception {
        String token = stripQuotes(rawUserinfo == null ? "" : rawUserinfo.trim());
        if (token.isEmpty()) {
            throw new IllegalArgumentException("Empty userinfo response");
        }
        if (token.startsWith("{")) {
            return JSONObjectUtils.parse(token);
        }

        int parts = token.split("\\.", -1).length;
        if (parts == 5) {
            System.out.println("Userinfo is JWE; decrypting with PRIVATE_KEY_USER_INFO");
            String inner = stripQuotes(decryptJwe(token).trim());
            return inner.startsWith("{")
                    ? JSONObjectUtils.parse(inner)
                    : SignedJWT.parse(inner).getJWTClaimsSet().getClaims();
        }
        if (parts == 3) {
            System.out.println("Userinfo is JWS; decoding JWT claims");
            return SignedJWT.parse(token).getJWTClaimsSet().getClaims();
        }
        throw new IllegalArgumentException("Unsupported userinfo compact format (" + parts + " parts)");
    }

    /**
     * eSignet encrypts with RSA-OAEP-256 + A256GCM using the RP encryption public key.
     * Inner payload is a signed JWT (JWS).
     */
    private String decryptJwe(String compactJwe) throws Exception {
        RSAKey rsaKey = parseJwk(encryptionKey);
        JWEObject jwe = JWEObject.parse(compactJwe);
        try {
            jwe.decrypt(new RSADecrypter(rsaKey));
        } catch (Exception e) {
            throw keyMismatchError(jwe, rsaKey, e);
        }
        System.out.println("JWE userinfo decrypted successfully");
        return jwe.getPayload().toString();
    }

    private static OAuth2AuthenticationException keyMismatchError(JWEObject jwe, RSAKey rsaKey, Exception e) {
        String tokenKid = jwe.getHeader().getKeyID();
        String localKid = rsaKey.getKeyID();
        int encryptedKeyBytes = jwe.getEncryptedKey() == null ? 0 : jwe.getEncryptedKey().decode().length;
        int localKeyBytes = rsaKey.getModulus() == null ? 0 : rsaKey.getModulus().decode().length;
        System.out.println("JWE decrypt failed: token_kid=" + tokenKid + " local_kid=" + localKid
                + " encrypted_key_bytes=" + encryptedKeyBytes + " local_key_bytes=" + localKeyBytes
                + " err=" + e.getMessage());
        String description = "JWE userinfo was encrypted with a different key than PRIVATE_KEY_USER_INFO. "
                + "token kid=" + tokenKid + " local kid=" + localKid + "; "
                + "encrypted CEK is " + encryptedKeyBytes + " bytes (" + encryptedKeyBytes * 8 + "-bit RSA) "
                + "but local private key is " + localKeyBytes + " bytes (" + localKeyBytes * 8 + "-bit). "
                + "Underlying: " + e.getMessage();
        return new OAuth2AuthenticationException(
                new OAuth2Error("userinfo_decrypt_failed", description, null), description, e);
    }

    /** Parse a JWK from JSON or base64-encoded JSON. */
    private static RSAKey parseJwk(String keyStr) throws Exception {
        if (!StringUtils.hasText(keyStr)) {
            throw new IllegalStateException("Encryption/private JWK is empty");
        }
        String raw = keyStr.trim().replaceAll("^['\"]|['\"]$", "");
        if (raw.startsWith("{")) {
            return RSAKey.parse(raw);
        }
        return RSAKey.parse(new String(Base64.getDecoder().decode(raw), StandardCharsets.UTF_8));
    }

    private static String stripQuotes(String value) {
        return value.replaceAll("^\"|\"$", "");
    }
}
