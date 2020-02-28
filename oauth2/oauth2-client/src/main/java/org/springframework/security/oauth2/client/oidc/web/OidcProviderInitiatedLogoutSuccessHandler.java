package org.springframework.security.oauth2.client.oidc.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.springframework.core.convert.TypeDescriptor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.oidc.logout.OidcLogoutValidatorFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.converter.ClaimConversionService;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.server.header.CacheControlServerHttpHeadersWriter;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URL;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class OidcProviderInitiatedLogoutSuccessHandler extends HttpStatusReturningLogoutSuccessHandler {

	private final ClientRegistrationRepository clientRegistrationRepository;
	private OidcLogoutValidatorFactory oidcLogoutValidatorFactory = new OidcLogoutValidatorFactory();

	public OidcProviderInitiatedLogoutSuccessHandler(ClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
	}

	// HeadersConfigurer
	@Override
	public void onLogoutSuccess(HttpServletRequest request,
			HttpServletResponse response,
			Authentication authentication) throws IOException {
		response.setHeader(HttpHeaders.CACHE_CONTROL,
				"no-cache, no-store"); // todo maybe CacheControlServerHttpHeadersWriter.CACHE_CONTRTOL_VALUE work ?
		response.setHeader(HttpHeaders.PRAGMA, CacheControlServerHttpHeadersWriter.PRAGMA_VALUE);


		if (authentication instanceof OAuth2AuthenticationToken && authentication.getPrincipal() instanceof OidcUser) {
			OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
			String registrationId = token.getAuthorizedClientRegistrationId();
			ClientRegistration clientRegistration = this.clientRegistrationRepository
					.findByRegistrationId(registrationId);

			OidcIdTokenDecoderFactory decoderFactory = new OidcIdTokenDecoderFactory();
			oidcLogoutValidatorFactory = new OidcLogoutValidatorFactory();
			decoderFactory.setJwtValidatorFactory(this.oidcLogoutValidatorFactory);
			decoderFactory.setClaimTypeConverterFactory(pClientRegistration -> new ClaimTypeConverter(
					createLogoutClaimTypeConverters()));

			JwtDecoder jwtDecoder = decoderFactory.createDecoder(clientRegistration);

			String logoutToken = request.getParameter("logout_token");
			Jwt jwt = jwtDecoder.decode(logoutToken);
		}


		if (!jwt.containsClaim(IdTokenClaimNames.EVENTS)) {
			throw new BadJwtException("");
		}

		// verify content of claim { "http://schemas.openid.net/event/backchannel-logout": {} }
		String eventsClaim = jwt.getClaim(IdTokenClaimNames.EVENTS);
		ObjectMapper objectMapper = new ObjectMapper();
		objectMapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
		Map<String, Object> map = objectMapper.readValue((String) jwt.getClaim(IdTokenClaimNames.EVENTS), Map.class);

		if(map.size() != 1 || map.entrySet().stream().noneMatch(entry -> "".equals(entry.getKey()) && entry.getValue().)){
			throw new BadJwtException("");
		}

		if (jwt.containsClaim(IdTokenClaimNames.NONCE)) {
			throw new BadJwtException("");
		}

		// LogoutTokenClaimsVerifier logoutTokenClaimsVerifier = new LogoutTokenClaimsVerifier();


		boolean invalidRequest = false;
		if (invalidRequest) {
			response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
			response.getWriter().flush();
		}

		boolean logoutFailed = false;
		if (logoutFailed) {
			response.setStatus(HttpServletResponse.SC_NOT_IMPLEMENTED);
			response.getWriter().flush();
		}

		boolean downstreamLogoutFailed = false;
		if (downstreamLogoutFailed) {
			response.setStatus(HttpServletResponse.SC_GATEWAY_TIMEOUT);
			response.getWriter().flush();
		}
		super.onLogoutSuccess(request, response, authentication);
	}

	private Map<String, Converter<Object, ?>> createLogoutClaimTypeConverters() {
		Converter<Object, ?> instantConverter = getConverter(TypeDescriptor.valueOf(Instant.class));
		Converter<Object, ?> urlConverter = getConverter(TypeDescriptor.valueOf(URL.class));
		Converter<Object, ?> stringConverter = getConverter(TypeDescriptor.valueOf(String.class));
		Converter<Object, ?> collectionStringConverter = getConverter(
				TypeDescriptor.collection(Collection.class, TypeDescriptor.valueOf(String.class)));

		Map<String, Converter<Object, ?>> claimTypeConverters = new HashMap<>();
		claimTypeConverters.put(IdTokenClaimNames.ISS, urlConverter);
		claimTypeConverters.put(IdTokenClaimNames.AUD, collectionStringConverter);
		claimTypeConverters.put(IdTokenClaimNames.IAT, instantConverter);
//		claimTypeConverters.put(IdTokenClaimNames.EVENTS, stringConverter);

		return claimTypeConverters;
	}

	private static Converter<Object, ?> getConverter(TypeDescriptor targetDescriptor) {
		final TypeDescriptor sourceDescriptor = TypeDescriptor.valueOf(Object.class);
		return source -> ClaimConversionService.getSharedInstance().convert(source, sourceDescriptor, targetDescriptor);
	}
}
