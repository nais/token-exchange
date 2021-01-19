package io.nais.security.oauth2.model

import com.nimbusds.jose.jwk.source.DefaultJWKSetCache
import com.nimbusds.jose.jwk.source.RemoteJWKSet.DEFAULT_HTTP_CONNECT_TIMEOUT
import com.nimbusds.jose.jwk.source.RemoteJWKSet.DEFAULT_HTTP_READ_TIMEOUT
import com.nimbusds.jose.jwk.source.RemoteJWKSet.DEFAULT_HTTP_SIZE_LIMIT
import com.nimbusds.jose.util.DefaultResourceRetriever
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeUnit.SECONDS

data class CacheProperties(
    val lifeSpan: Long,
    val refreshTime: Long,
    val timeUnit: TimeUnit = SECONDS,
    val connectionTimeout: Int = DEFAULT_HTTP_CONNECT_TIMEOUT,
    val readTimeOut: Int = DEFAULT_HTTP_READ_TIMEOUT,
    val sizeLimit: Int = DEFAULT_HTTP_SIZE_LIMIT
) {
    val configurableJWKSetCache = DefaultJWKSetCache(
        this.lifeSpan,
        this.refreshTime,
        this.timeUnit
    )

    val configurableResourceRetriever = DefaultResourceRetriever(
        this.connectionTimeout,
        this.readTimeOut,
        this.sizeLimit
    )
}
