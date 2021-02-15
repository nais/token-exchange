package io.nais.security.oauth2.token

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.BadJOSEException
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.BadJWTException
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier
import com.nimbusds.oauth2.sdk.OAuth2Error
import com.nimbusds.oauth2.sdk.ParseException
import io.nais.security.oauth2.model.OAuth2Exception
import java.time.Duration
import java.time.Instant
import java.util.HashSet

fun JWTClaimsSet.sign(rsaKey: RSAKey): SignedJWT =
    SignedJWT(
        JWSHeader.Builder(JWSAlgorithm.RS256)
            .keyID(rsaKey.keyID)
            .type(JOSEObjectType.JWT).build(),
        this
    ).apply {
        sign(RSASSASigner(rsaKey.toPrivateKey()))
    }

fun SignedJWT.expiresIn(): Long =
    Duration.between(Instant.now(), this.jwtClaimsSet.expirationTime.toInstant()).seconds

@Throws(BadJOSEException::class, JOSEException::class, BadJWTException::class)
fun SignedJWT.verify(issuer: String, keySelector: JWSVerificationKeySelector<SecurityContext?>, optionalClaims: List<String>): JWTClaimsSet {
    return verify(
        DefaultJWTClaimsVerifier(
            JWTClaimsSet.Builder()
                .issuer(issuer)
                .build(),
            HashSet(
                optionalClaims
            )
        ),
        keySelector
    )
}

@Throws(BadJOSEException::class, JOSEException::class, BadJWTException::class)
fun SignedJWT.verify(jwtClaimsSetVerifier: JWTClaimsSetVerifier<SecurityContext?>, jwkSet: JWKSet): JWTClaimsSet {
    return verify(
        jwtClaimsSetVerifier,
        JWSVerificationKeySelector(
            JWSAlgorithm.RS256,
            ImmutableJWKSet(jwkSet)
        )
    )
}

@Throws(OAuth2Exception::class)
fun SignedJWT.verify(
    jwtClaimsSetVerifier: JWTClaimsSetVerifier<SecurityContext?>,
    keySelector: JWSVerificationKeySelector<SecurityContext?>
): JWTClaimsSet {
    try {
        val jwtProcessor: ConfigurableJWTProcessor<SecurityContext?> = DefaultJWTProcessor()
        jwtProcessor.jwsKeySelector = keySelector
        jwtProcessor.jwtClaimsSetVerifier = jwtClaimsSetVerifier
        return jwtProcessor.process(this, null)
    } catch (t: Throwable) {
        throw OAuth2Exception(OAuth2Error.INVALID_REQUEST.setDescription("token verification failed: ${t.message}"), t)
    }
}

@Throws(OAuth2Exception::class)
internal fun String.toJwt(): SignedJWT = try {
    SignedJWT.parse(this)
} catch (t: Throwable) {
    throw OAuth2Exception(OAuth2Error.INVALID_REQUEST.setDescription("invalid request, cannot parse token"), t)
}

@Throws(ParseException::class)
internal fun String.toRSAKey() = RSAKey.parse(this)

internal fun RSAKey.toJSON() = this.toJSONString()
