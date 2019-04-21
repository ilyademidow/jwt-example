package hello.jwt;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.ErrorCodes;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Component
public class JwtTokenProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtTokenProvider.class);
    private static final String ISSUER = "ukva-auth-server";
    private static final String AUDIENCE = "alfa-works";
    private static final Integer CLOCK_SKEW_SECONDS = 30;
    private static final Integer EXPIRATION_MINUTES = 100;
    private static final Integer VALID_BEFORE_MINUTES = 2;
    private static final String OPERATIONS = "operations";
    private static final String AUTH_HEADER = "Authorization";
    private RsaJsonWebKey rsaJsonWebKey;
    private JwtConsumer jwtConsumer;

    @PostConstruct
    protected void init() {
        try {
            rsaJsonWebKey = RsaJwkGenerator.generateJwk(2048);

            // Use JwtConsumerBuilder to construct an appropriate JwtConsumer, which will
            // be used to validate and process the JWT.
            // The specific validation requirements for a JWT are context dependent, however,
            // it typically advisable to require a (reasonable) expiration time, a trusted issuer, and
            // and audience that identifies your system as the intended recipient.
            // If the JWT is encrypted too, you need only provide a decryption key or
            // decryption key resolver to the builder.
            jwtConsumer = new JwtConsumerBuilder()
                    .setRequireExpirationTime() // the JWT must have an expiration time
                    .setAllowedClockSkewInSeconds(CLOCK_SKEW_SECONDS) // allow some leeway in validating time based claims to account for clock skew
                    .setRequireSubject() // the JWT must have a subject claim
                    .setExpectedIssuer(ISSUER) // whom the JWT needs to have been issued by
                    .setExpectedAudience(AUDIENCE) // to whom the JWT is intended for
                    .setVerificationKey(rsaJsonWebKey.getKey()) // verify the signature with the public key
                    .setJwsAlgorithmConstraints( // only allow the expected signature algorithm(s) in the given context
                            new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, // which is only RS256 here
                                    AlgorithmIdentifiers.RSA_USING_SHA256))
                    .build(); // create the JwtConsumer instance
        } catch (JoseException e) {
            e.printStackTrace();
        }
    }

    /**
     * Write user credentials by the represented token
     * @param token JSON Web Token which has been issued before
     * @return UsernamePasswordAuthenticationToken
     */
    public Authentication getAuthentication(String token) {
        User userDetails = new User(getUsername(token), "", getRoles(token));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    /**
     * Extract JWT from the Request Header
     * @param req HttpServletRequest
     * @return JWT
     */
    public String resolveToken(HttpServletRequest req) {
        String bearerToken = req.getHeader(AUTH_HEADER);
        if (bearerToken == null) {
            return null;
        }
        return bearerToken;
    }

    /**
     * Generate JSON Web Token for the particular user. The rest of parameters are constants.
     * @param username Who granted
     * @param operations User roles
     * @return JSON Web Token
     */
    public String createToken(String username, List<String> operations) {
        // Give the JWK a Key ID (kid), which is just the polite thing to do
        rsaJsonWebKey.setKeyId("k1");

        // Create the Claims, which will be the content of the JWT
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(ISSUER);  // who creates the token and signs it
        claims.setAudience(AUDIENCE); // to whom the token is intended to be sent
        claims.setExpirationTimeMinutesInTheFuture(EXPIRATION_MINUTES); // time when the token will expire (10 minutes from now)
        claims.setGeneratedJwtId(); // a unique identifier for the token
        claims.setIssuedAtToNow();  // when the token was issued/created (now)
        claims.setNotBeforeMinutesInThePast(VALID_BEFORE_MINUTES); // time before which the token is not yet valid (2 minutes ago)
        claims.setSubject(username); // the subject/principal is whom the token is about
        claims.setStringListClaim(OPERATIONS, operations); // multi-valued claims work too and will end up as a JSON array

        // A JWT is a JWS and/or a JWE with JSON claims as the payload.
        // In this example it is a JWS so we create a JsonWebSignature object.
        JsonWebSignature jws = new JsonWebSignature();

        // The payload of the JWS is JSON content of the JWT Claims
        jws.setPayload(claims.toJson());

        // The JWT is signed using the private key
        jws.setKey(rsaJsonWebKey.getPrivateKey());

        // Set the Key ID (kid) header because it's just the polite thing to do.
        // We only have one key in this example but a using a Key ID helps
        // facilitate a smooth key rollover process
        jws.setKeyIdHeaderValue(rsaJsonWebKey.getKeyId());

        // Set the signature algorithm on the JWT/JWS that will integrity protect the claims
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

        // Sign the JWS and produce the compact serialization or the complete JWT/JWS
        // representation, which is a string consisting of three dot ('.') separated
        // base64url-encoded parts in the form Header.Payload.Signature
        // If you wanted to encrypt it, you can simply set this jwt as the payload
        // of a JsonWebEncryption object and set the cty (Content Type) header to "jwt".

        // Now you can do something with the JWT. Like send it to some other party
        // over the clouds and through the interwebs.
        try {
            return jws.getCompactSerialization();
        } catch (JoseException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    /**
     * Validate the represented token
     *
     * @param jwt JSON Web Token which has been issued before
     * @return Is token valid
     */
    public boolean validateToken(String jwt) {
        try {
            //  Validate the JWT and process it to the Claims
            jwtConsumer.processToClaims(jwt);
            return true;
        } catch (InvalidJwtException e) {
            // Programmatic access to (some) specific reasons for JWT invalidity is also possible
            // should you want different error handling behavior for certain conditions.
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug(e.getStackTrace().toString());
            }
            // Whether or not the JWT has expired being one common reason for invalidity
            if (e.hasExpired()) {
                try {
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("JWT expired at " + e.getJwtContext().getJwtClaims().getExpirationTime() + e.getStackTrace().toString());
                    }
                    throw new RuntimeException("JWT expired at " + e.getJwtContext().getJwtClaims().getExpirationTime());
                } catch (MalformedClaimException malformedException) {
                    LOGGER.debug(malformedException.getMessage() + malformedException.getStackTrace().toString());
                }
            }

            // Or maybe the audience was invalid
            if (e.hasErrorCode(ErrorCodes.AUDIENCE_INVALID)) {
                try {
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("JWT had wrong audience: " + e.getJwtContext().getJwtClaims().getAudience());
                    }
                    throw new RuntimeException("JWT had wrong audience: " + e.getJwtContext().getJwtClaims().getAudience());
                } catch (MalformedClaimException malformedException) {
                    LOGGER.debug(malformedException.getMessage() + malformedException.getStackTrace().toString());
                }
            }
            return false;
        }
    }

    private String getUsername(String token) {
        try {
            return jwtConsumer.processToClaims(token).getSubject();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private Collection<? extends GrantedAuthority> getRoles(String token) {
        try {
            Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
            jwtConsumer.processToClaims(token).getStringListClaimValue(OPERATIONS).forEach(oper -> authorities.add(new SimpleGrantedAuthority(oper)));
            return authorities;
        } catch (InvalidJwtException | MalformedClaimException e) {
            e.printStackTrace();
            return null;
        }
    }
}
