package org.springframework.security.oauth2.client.oidc.logout;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.openid.connect.sdk.claims.LogoutTokenClaimsSet;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.net.URL;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class OidcLogoutValidator implements OAuth2TokenValidator<Jwt> {
	private static final Duration DEFAULT_CLOCK_SKEW = Duration.ofSeconds(60);
	private final ClientRegistration clientRegistration;
	private Duration clockSkew = DEFAULT_CLOCK_SKEW;
	private Clock clock = Clock.systemUTC();

	public OidcLogoutValidator(ClientRegistration clientRegistration) {
		Assert.notNull(clientRegistration, "clientRegistration cannot be null");
		this.clientRegistration = clientRegistration;
	}

	private static OAuth2Error invalidIdToken(Map<String, Object> invalidClaims) {
		return new OAuth2Error("invalid_logout_token",
				"The Logout contains invalid claims: " + invalidClaims,
				"https://openid.net/specs/openid-connect-backchannel-1_0.html#rfc.section.2.4");
	}

	private static Map<String, Object> validateRequiredClaims(Jwt idToken) {
		Map<String, Object> requiredClaims = new HashMap<>();

		URL issuer = idToken.getIssuer();
		if (issuer == null) {
			requiredClaims.put(IdTokenClaimNames.ISS, issuer);
		}
		List<String> audience = idToken.getAudience();
		if (CollectionUtils.isEmpty(audience)) {
			requiredClaims.put(IdTokenClaimNames.AUD, audience);
		}
		Instant issuedAt = idToken.getIssuedAt();
		if (issuedAt == null) {
			requiredClaims.put(IdTokenClaimNames.IAT, issuedAt);
		}
		String jti = idToken.getId();
		if (jti == null) {
			requiredClaims.put(IdTokenClaimNames.JTI, jti);
		}
		if (!idToken.containsClaim(IdTokenClaimNames.EVENTS)) {
			requiredClaims.put(IdTokenClaimNames.EVENTS, null);
		}
		return requiredClaims;
	}

	private static Map<String, Object> validateProhibitedNonceClaim(Jwt idToken) {
		Map<String, Object> prohibitedClaims = new HashMap<>();

		if (idToken.containsClaim(IdTokenClaimNames.NONCE)) {
			prohibitedClaims.put(IdTokenClaimNames.NONCE, idToken.getClaim(IdTokenClaimNames.NONCE));
		}
		return prohibitedClaims;
	}

	@Override
	public OAuth2TokenValidatorResult validate(Jwt token) {
		// 2.6.  Logout Token Validation
		// https://openid.net/specs/openid-connect-backchannel-1_0.html#rfc.section.2.6

		Map<String, Object> invalidClaims = validateRequiredClaims(token);
		if (!invalidClaims.isEmpty()) {
			return OAuth2TokenValidatorResult.failure(invalidIdToken(invalidClaims));
		}

		// 2. The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery)
		// MUST exactly match the value of the iss (issuer) Claim.
		// TODO Depends on gh-4413

		// 3. The Client MUST validate that the aud (audience) Claim contains its client_id value
		// registered at the Issuer identified by the iss (issuer) Claim as an audience.
		// The aud (audience) Claim MAY contain an array with more than one element.
		// The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience,
		// or if it contains additional audiences not trusted by the Client.
		if (!token.getAudience().contains(this.clientRegistration.getClientId())) {
			invalidClaims.put(IdTokenClaimNames.AUD, token.getAudience());
		}

		// 4. If the ID Token contains multiple audiences,
		// the Client SHOULD verify that an azp Claim is present.
		String authorizedParty = token.getClaimAsString(IdTokenClaimNames.AZP);
		if (token.getAudience().size() > 1 && authorizedParty == null) {
			invalidClaims.put(IdTokenClaimNames.AZP, authorizedParty);
		}

		// 5. If an azp (authorized party) Claim is present,
		// the Client SHOULD verify that its client_id is the Claim Value.
		if (authorizedParty != null && !authorizedParty.equals(this.clientRegistration.getClientId())) {
			invalidClaims.put(IdTokenClaimNames.AZP, authorizedParty);
		}

		// 6. The iat Claim can be used to reject tokens that were issued too far away from the current time,
		// limiting the amount of time that nonces need to be stored to prevent attacks.
		// The acceptable range is Client specific.
		Instant now = Instant.now(this.clock);
		if (now.plus(this.clockSkew).isBefore(token.getIssuedAt())) {
			invalidClaims.put(IdTokenClaimNames.IAT, token.getIssuedAt());
		}

		// todo Verify that the Logout Token contains a sub Claim, a sid Claim, or both.
		invalidClaims.putAll(validateSubSidClaims(token));


		// Verify that the Logout Token contains an events Claim whose value is JSON object
		// containing the member name http://schemas.openid.net/event/backchannel-logout.
		try {
			ObjectMapper objectMapper = new ObjectMapper();
//			objectMapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
			// todo JSONObject
			JsonNode events = objectMapper.readTree(token.<String>getClaim(IdTokenClaimNames.EVENTS));
			Iterator<Map.Entry<String, JsonNode>> fields = events.fields();
			if (fields.hasNext()) {
				Map.Entry<String, JsonNode> field = fields.next();
				if (fields.hasNext() || !LogoutTokenClaimsSet.EVENT_TYPE.equals(field.getKey()) || !field.getValue()
						.isEmpty()) {
					invalidClaims.put(IdTokenClaimNames.EVENTS, events);
				}
			}
		} catch (JsonProcessingException e) {
			invalidClaims.put(IdTokenClaimNames.EVENTS, "Cannot be parsed");
		}

		invalidClaims.putAll(validateProhibitedNonceClaim(token));

		// Verify that the Logout Token does not contain a nonce Claim.
		if (!invalidClaims.isEmpty()) {
			return OAuth2TokenValidatorResult.failure(invalidIdToken(invalidClaims));
		}

		// todo Optionally verify that another Logout Token with the same jti value has not been recently received.

		return OAuth2TokenValidatorResult.success();
	}

	private Map<String, Object> validateSubSidClaims(Jwt token) {
		Map<String, Object> invalidClaims = new HashMap<>();
		Object sidRequiredMetaData = this.clientRegistration.getProviderDetails().getConfigurationMetadata().get("backchannel_logout_session_required");
		boolean sidRequired = false;
		if(sidRequiredMetaData instanceof Boolean) {
			sidRequired = (boolean) sidRequiredMetaData;
		}
		if (!token.containsClaim(IdTokenClaimNames.SID) && (sidRequired || !token.containsClaim(IdTokenClaimNames.SUB))) {
			// todo sid or sub
			if(!token.containsClaim(IdTokenClaimNames.SID)) {
				invalidClaims.put(IdTokenClaimNames.SID, token.getClaim(IdTokenClaimNames.SID));
			}
		}
		return invalidClaims;
	}
}
