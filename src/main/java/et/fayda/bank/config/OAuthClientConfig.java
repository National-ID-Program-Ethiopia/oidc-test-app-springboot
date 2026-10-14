package et.fayda.bank.config;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.NimbusJwtClientAuthenticationParametersConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenValidator;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Configuration
public class OAuthClientConfig {

    private final String privateKeyBase64;
    private final Set<SignatureAlgorithm> idTokenAlgorithms;

    public OAuthClientConfig(@Value("${PRIVATE_KEY}") String privateKeyBase64,
                             @Value("${FAYDA_ID_TOKEN_SIGNING_ALG:PS256,RS256}") String idTokenAlgorithms) {
        this.privateKeyBase64 = privateKeyBase64;
        this.idTokenAlgorithms = parseAlgorithms(idTokenAlgorithms);
    }

    private static Set<SignatureAlgorithm> parseAlgorithms(String names) {
        Set<SignatureAlgorithm> algorithms = new LinkedHashSet<>();
        for (String name : names.split(",")) {
            if (name.isBlank()) {
                continue;
            }
            SignatureAlgorithm algorithm = SignatureAlgorithm.from(name.trim());
            if (algorithm == null) {
                throw new IllegalStateException("Unsupported algorithm in FAYDA_ID_TOKEN_SIGNING_ALG: " + name.trim());
            }
            algorithms.add(algorithm);
        }
        if (algorithms.isEmpty()) {
            throw new IllegalStateException("FAYDA_ID_TOKEN_SIGNING_ALG must list at least one algorithm, e.g. PS256,RS256");
        }
        return algorithms;
    }

    private RSAKey loadRsaKey() {
        try {
            byte[] decoded = Base64.getDecoder().decode(privateKeyBase64.trim());
            String jwkJson = new String(decoded, StandardCharsets.UTF_8);
            // Nimbus adds the JWK's kid to the assertion header and a random jti to its claims.
            return RSAKey.parse(jwkJson);

        } catch (Exception e) {
            throw new IllegalStateException("Failed to load Fayda RSA private key", e);
        }
    }

    @Bean
    public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
        RSAKey rsaKey = loadRsaKey();

        NimbusJwtClientAuthenticationParametersConverter<OAuth2AuthorizationCodeGrantRequest> jwtConverter =
                new NimbusJwtClientAuthenticationParametersConverter<>(
                        (ClientRegistration registration) -> rsaKey
                );

        OAuth2AuthorizationCodeGrantRequestEntityConverter requestEntityConverter =
                new OAuth2AuthorizationCodeGrantRequestEntityConverter();
        requestEntityConverter.addParametersConverter(jwtConverter);

        DefaultAuthorizationCodeTokenResponseClient tokenResponseClient =
                new DefaultAuthorizationCodeTokenResponseClient();
        tokenResponseClient.setRequestEntityConverter(requestEntityConverter);

        return tokenResponseClient;
    }

    /**
     * ID token decoder that accepts every algorithm in FAYDA_ID_TOKEN_SIGNING_ALG (default PS256,RS256).
     * eSignet signs with PS256 while its discovery document advertises RS256, and Spring's
     * OidcIdTokenDecoderFactory allows only one algorithm. Validation (timestamps, iss/aud/azp) and claim
     * conversion are the same as Spring's. A signature failure names the token's alg/kid and the kids the
     * JWKS actually publishes, instead of Nimbus's bare "Another algorithm expected, or no matching key(s) found".
     */
    @Bean
    public JwtDecoderFactory<ClientRegistration> idTokenDecoderFactory() {
        Map<String, JwtDecoder> decoders = new ConcurrentHashMap<>();
        return registration -> decoders.computeIfAbsent(registration.getRegistrationId(), id -> {
            NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(registration.getProviderDetails().getJwkSetUri())
                    .jwsAlgorithms(algorithms -> algorithms.addAll(idTokenAlgorithms))
                    .build();
            decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                    new JwtTimestampValidator(), new OidcIdTokenValidator(registration)));
            decoder.setClaimSetConverter(new ClaimTypeConverter(
                    OidcIdTokenDecoderFactory.createDefaultClaimTypeConverters()));
            return token -> {
                try {
                    return decoder.decode(token);
                } catch (BadJwtException e) {
                    throw new BadJwtException(e.getMessage() + ". " + describeKeyMismatch(token, registration), e);
                }
            };
        });
    }

    private String describeKeyMismatch(String token, ClientRegistration registration) {
        String jwkSetUri = registration.getProviderDetails().getJwkSetUri();
        String header;
        try {
            JWSHeader jws = SignedJWT.parse(token).getHeader();
            header = "ID token header alg=" + jws.getAlgorithm() + " kid=" + jws.getKeyID();
        } catch (Exception e) {
            header = "ID token header unreadable (" + e.getMessage() + ")";
        }
        String published;
        try {
            published = JWKSet.load(URI.create(jwkSetUri).toURL()).getKeys().stream()
                    .map(k -> "kid=" + k.getKeyID() + " kty=" + k.getKeyType() + " alg=" + k.getAlgorithm()
                            + " use=" + k.getKeyUse())
                    .collect(Collectors.joining("; ", "[", "]"));
        } catch (Exception e) {
            published = "could not be loaded (" + e.getMessage() + ")";
        }
        return header + " (accepted algs=" + idTokenAlgorithms + ", set by FAYDA_ID_TOKEN_SIGNING_ALG); JWKS "
                + jwkSetUri + " publishes " + published;
    }
}
