package com.example.app.web.server.config;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.NimbusJwtClientAuthenticationParametersConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

/**
 * Web security configuration.
 */
@Configuration
public class WebSecurityConfiguration {

	private final Map<String, JwtDecoder> jwtDecoders = new ConcurrentHashMap<>();

	/**
	 * Gets the JWKS for encryption/decryption and signing/verification.
	 * @param resourceLoader the resource loader
	 * @param applicationProperties the application properties
	 * @return the JWKS
	 * @throws IOException the exception
	 * @throws ParseException the exception
	 */
	@Bean
	JWKSet jwks(ResourceLoader resourceLoader, ApplicationProperties applicationProperties)
			throws IOException, ParseException {
		try (InputStream inputStream = resourceLoader.getResource(applicationProperties.getJwks()).getInputStream()) {
			return JWKSet.load(inputStream);
		}
	}

	/**
	 * Configure the security filter chain.
	 * @param http the http security
	 * @param jwks the JWKS
	 * @return the security filter chain
	 * @throws Exception the exception
	 */
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http, JWKSet jwks) throws Exception {
		DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient = accessTokenResponseClient(jwks);
		return http
			.authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests
				.requestMatchers(new AntPathRequestMatcher("/oauth2/jwks"))
				.anonymous())
			.authorizeHttpRequests(
					authorizeHttpRequests -> authorizeHttpRequests.requestMatchers(new AntPathRequestMatcher("/**"))
						.authenticated())
			.oauth2Login(oauth2Login -> oauth2Login
				.tokenEndpoint(tokenEndpoint -> tokenEndpoint.accessTokenResponseClient(accessTokenResponseClient)))
			.build();
	}

	/**
	 * Configure the JWT decoder used to decode the ID Token.
	 * @param jwkSet the JWKS with the decryption key to decrypt the ID Token
	 * @return the jwt decoder factory to decode the ID Token
	 */
	@Bean
	JwtDecoderFactory<ClientRegistration> jwtDecoderFactory(JWKSet jwkSet) {
		/*
		 * The default implementation is OidcIdTokenDecoderFactory but its customization
		 * is limited.
		 */
		return clientRegistration -> {
			return jwtDecoders.computeIfAbsent(clientRegistration.getRegistrationId(), key -> {
				DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();

				// Configuration to decrypt the JWE
				JWEDecryptionKeySelector<SecurityContext> jweKeySelector = new JWEDecryptionKeySelector<>(
						JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A256CBC_HS512, new ImmutableJWKSet<>(jwkSet));
				jwtProcessor.setJWEKeySelector(jweKeySelector);

				// Configuration to verify the JWS
				JWSVerificationKeySelector<SecurityContext> jwsKeySelector;
				JWKSource<SecurityContext> jwkSource = jwkSource(clientRegistration);
				jwsKeySelector = new JWSVerificationKeySelector<>(JWSAlgorithm.ES256, new JWKSource<SecurityContext>() {
					@Override
					public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) throws KeySourceException {
						// The ECDSAVerifier throws a JOSE exception instead of returning
						// false if it is
						// an incorrect algorithm
						List<JWK> jwk = jwkSource.get(jwkSelector, context);
						return jwk.stream().filter(key -> {
							if (key instanceof ECKey ecKey) {
								if (Curve.P_256.equals(ecKey.getCurve())) {
									// The actual keys don't specific alg but only specify
									// crv
									return true;
								}
							}
							return false;
						}).toList();
					}
				});
				jwtProcessor.setJWSKeySelector(jwsKeySelector);
				return new NimbusJwtDecoder(jwtProcessor);
			});
		};
	}

	/**
	 * Gets the jwk source to use for a client registration.
	 * @param clientRegistration the client registration
	 * @return the jwk source
	 */
	private JWKSource<SecurityContext> jwkSource(ClientRegistration clientRegistration) {
		String jwkSetUri = clientRegistration.getProviderDetails().getJwkSetUri();
		try {
			return new RemoteJWKSet<SecurityContext>(new URL(jwkSetUri));
		}
		catch (MalformedURLException e) {
			throw new IllegalArgumentException(e);
		}
	}

	/**
	 * Gets the access token response client configured for private_key_jwt
	 * authentication.
	 * @param jwks the JWKS
	 * @return the access token response client
	 */
	private DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient(JWKSet jwks) {
		Function<ClientRegistration, JWK> jwkResolver = clientRegistration -> jwks.getKeys()
			.stream()
			.filter(jwk -> KeyUse.SIGNATURE.equals(jwk.getKeyUse()))
			.findFirst()
			.get();
		NimbusJwtClientAuthenticationParametersConverter<OAuth2AuthorizationCodeGrantRequest> parametersConverter = new NimbusJwtClientAuthenticationParametersConverter<>(
				jwkResolver);
		parametersConverter.setJwtClientAssertionCustomizer(context -> {
			// Configure the aud claim with the iss value
			context.getClaims()
				.audience(List.of(context.getAuthorizationGrantRequest()
					.getClientRegistration()
					.getProviderDetails()
					.getIssuerUri()));
			// Set the typ
			context.getHeaders().type("JWT");
		});

		OAuth2AuthorizationCodeGrantRequestEntityConverter authorizationCodeGrantRequestEntityConverter = new OAuth2AuthorizationCodeGrantRequestEntityConverter();
		authorizationCodeGrantRequestEntityConverter.addParametersConverter(parametersConverter);

		DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
		accessTokenResponseClient.setRequestEntityConverter(authorizationCodeGrantRequestEntityConverter);
		return accessTokenResponseClient;
	}

}
