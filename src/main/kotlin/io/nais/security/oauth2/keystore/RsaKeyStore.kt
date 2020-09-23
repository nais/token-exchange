package io.nais.security.oauth2.keystore

import io.nais.security.oauth2.config.RsaKeyStoreProperties
import io.nais.security.oauth2.token.toJSON
import io.nais.security.oauth2.token.toRSAKey
import io.nais.security.oauth2.utils.generateRsaKey
import kotliquery.Query
import kotliquery.Row
import kotliquery.queryOf
import kotliquery.sessionOf
import kotliquery.using
import mu.KotlinLogging
import org.slf4j.Logger
import java.time.LocalDateTime

private val log: Logger = KotlinLogging.logger { }

class RsaKeyStore(
    private val rsaKeyStoreProperties: RsaKeyStoreProperties
) {
    private val dataSource = rsaKeyStoreProperties.dataSource

    companion object {
        private const val TABLE_NAME = "rsakeys"
        const val ID = 1L
    }

    fun read() = using(sessionOf(dataSource)) { session ->
        session.run(
            queryOf("""SELECT * FROM $TABLE_NAME""")
                .map {
                    it.mapToRsaKeys()
                }.asSingle
        )
        /*
        *  TODO This is a bit of "code smell"...
        * This will work for a clean empty DB - But ff their is some problems with the db,
        * we really just want to throw an runtime exception, not overwrite the existing keys
        * making everything out of sync.
        * ?: initKeyStorage() should be replaced with: } ?: throw RuntimeException("No keys found in the database")
        * That leaves us with the problem of populating the empty db of rsakeys the first time..
        * */
    } ?: initKeyStorage()

    private fun Row.mapToRsaKeys(): RsaKeys {
        return RsaKeys(
            currentKey = this.string("current_key").toRSAKey(),
            previousKey = this.string("previous_key").toRSAKey(),
            nextKey = this.string("next_key").toRSAKey(),
            expiry = this.localDateTime("expiry")
        ).toKey()
    }

    fun initKeyStorage() = initRSAKeys().apply {
        save(this)
        log.info("RSA KEY initialised, next expiry: ${this.expiry}")
        return this
    }

    private fun initRSAKeys() = RsaKeys(
        currentKey = generateRsaKey(),
        previousKey = generateRsaKey(),
        nextKey = generateRsaKey(),
        expiry = LocalDateTime.now().plus(rsaKeyStoreProperties.rotationInterval)
    )

    fun save(rsaKeys: RsaKeys) =
        using(sessionOf(dataSource)) { session ->
            session.run(
                modify(
                    rsaKeys
                ).asUpdate
            )
        }

    private fun modify(rsaKeys: RsaKeys): Query {
        return queryOf(
            """
            INSERT INTO $TABLE_NAME(id, current_key, previous_key, next_key, expiry) VALUES (:id, :current_key, :previous_key, :next_key, :expiry)
            ON CONFLICT (id)
                DO UPDATE SET
                current_key=:current_key, previous_key=:previous_key, next_key=:next_key, expiry=:expiry;
            """.trimMargin(),
            mapOf(
                "id" to ID,
                "current_key" to rsaKeys.currentKey.toJSON(),
                "previous_key" to rsaKeys.previousKey.toJSON(),
                "next_key" to rsaKeys.nextKey.toJSON(),
                "expiry" to rsaKeys.expiry
            )
        )
    }
}
