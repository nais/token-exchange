package io.nais.security.oauth2.mock

import com.nimbusds.jose.jwk.JWKSet
import io.ktor.server.engine.applicationEngineEnvironment
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.util.KtorExperimentalAPI
import io.nais.security.oauth2.authentication.BearerTokenAuth
import io.nais.security.oauth2.config.AppConfiguration
import io.nais.security.oauth2.config.ClientRegistrationAuthProperties
import io.nais.security.oauth2.routing.DefaultRouting
import io.nais.security.oauth2.tokenExchangeApp
import mu.KotlinLogging
import no.nav.security.mock.oauth2.MockOAuth2Server
import no.nav.security.mock.oauth2.OAuth2Config
import java.net.InetAddress
import java.net.URL

val log = KotlinLogging.logger { }

private val jwkerJwks = "jwker-jwks.json".asResource().readText().let {
    JWKSet.parse(it)
}

@KtorExperimentalAPI
fun main() {
    val mockOAuth2Server: MockOAuth2Server = startMockOAuth2Server()

    val clientRegistrationAuthProps = ClientRegistrationAuthProperties(
        identityProviderWellKnownUrl = mockOAuth2Server.wellKnownUrl("/aadmock").toString(),
        acceptedAudience = listOf("tokendings"),
        acceptedRoles = BearerTokenAuth.ACCEPTED_ROLES_CLAIM_VALUE,
        softwareStatementJwks = jwkerJwks
    )

    val config: AppConfiguration = mockConfig(mockOAuth2Server, clientRegistrationAuthProps)

    embeddedServer(
        Netty,
        applicationEngineEnvironment {
            connector {
                port = config.serverProperties.port
            }
            module {
                tokenExchangeApp(config, DefaultRouting(config))
            }
        }
    ).start(wait = true)
}

private fun startMockOAuth2Server(): MockOAuth2Server =
    MockOAuth2Server(
        OAuth2Config(
            interactiveLogin = true
        )
    ).apply {
        this.start(InetAddress.getByName("localhost"), 1111)
    }

fun String.asResource(): URL = object {}.javaClass.classLoader.getResource(this)!!
