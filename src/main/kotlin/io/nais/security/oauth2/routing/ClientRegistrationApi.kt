package io.nais.security.oauth2.routing

import com.nimbusds.jwt.SignedJWT
import io.ktor.application.call
import io.ktor.auth.authenticate
import io.ktor.http.HttpStatusCode
import io.ktor.request.receive
import io.ktor.response.respond
import io.ktor.routing.Route
import io.ktor.routing.delete
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.routing.route
import io.nais.security.oauth2.authentication.BearerTokenAuth
import io.nais.security.oauth2.config.AppConfiguration
import io.nais.security.oauth2.model.AccessPolicy
import io.nais.security.oauth2.model.ClientRegistration
import io.nais.security.oauth2.model.ClientRegistrationRequest
import io.nais.security.oauth2.model.GrantType
import io.nais.security.oauth2.model.OAuth2Client
import io.nais.security.oauth2.model.SoftwareStatement

internal fun Route.clientRegistrationApi(config: AppConfiguration) {
    authenticate(BearerTokenAuth.CLIENT_REGISTRATION_AUTH) {
        route("/registration/client") {
            post {
                /*val adminClient = call.principal<JWTPrincipal>()?.payload?.subject
                    ?.let { config.clientRegistry.findClient(it) }
                    ?: throw OAuth2Exception(OAuth2Error.INVALID_CLIENT)*/

                val request: ClientRegistrationRequest = call.receive(ClientRegistrationRequest::class)
                // TODO: add verfication of signature back in when ready
                // val softwareStatement = request.verifySoftwareStatement(adminClient.jwkSet)
                val softwareStatement = request.parseSoftwareStatement()
                val grantTypes: List<String> = when {
                    request.grantTypes.isEmpty() -> listOf(GrantType.TOKEN_EXCHANGE_GRANT)
                    else -> request.grantTypes
                }
                val clientToRegister = OAuth2Client(
                    softwareStatement.appId,
                    request.jwks,
                    AccessPolicy(softwareStatement.accessPolicyInbound),
                    AccessPolicy(softwareStatement.accessPolicyOutbound),
                    request.scopes,
                    grantTypes
                )
                config.clientRegistry.registerClient(clientToRegister)
                call.respond(
                    HttpStatusCode.Created, ClientRegistration(
                        clientToRegister.clientId,
                        clientToRegister.jwks,
                        request.softwareStatement,
                        clientToRegister.allowedGrantTypes,
                        "private_key_jwt"
                    )
                )
            }
            delete("/{clientId}") {
                val clientId = call.parameters["clientId"]
                if (clientId != null) {
                    config.clientRegistry.deleteClient(clientId)
                    call.respond(HttpStatusCode.NoContent)
                }
            }
            get {
                call.respond(config.clientRegistry.findAll())
            }
            get("/{clientId}") {
                val client: OAuth2Client? = call.parameters["clientId"]
                    ?.let { config.clientRegistry.findClient(it) }
                when (client) {
                    null -> call.respond(HttpStatusCode.NotFound, "client not found")
                    else -> call.respond(client)
                }
            }
        }
    }
}

fun ClientRegistrationRequest.parseSoftwareStatement(): SoftwareStatement =
    SoftwareStatement.fromJson(SignedJWT.parse(this.softwareStatement).jwtClaimsSet.toJSONObject().toJSONString())
