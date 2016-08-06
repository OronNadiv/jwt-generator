const EXPIRATION_IN_SECONDS = 300
const jwt = require('jsonwebtoken')
const Promise = require('bluebird')
const http = require('http-as-promised')
const url = require('url')

const cacheOptions = {
  max: 10,
  maxAge: Math.floor(EXPIRATION_IN_SECONDS * 1000 * 0.9),
  maxElements: 1000
}

const cache = require('lru-cache')(cacheOptions)

class JWTGenerator {
  constructor (loginUrl, privateKey, issuer) {
    this.issuer = issuer
    this.loginUrl = loginUrl
    this.privateKey = privateKey
  }

  _getKey (subject, audience, payload) {
    return `issuer: ${this.issuer}
loginUrl: ${this.loginUrl}
privateKey: ${this.privateKey}
subject: ${subject}
audience: ${audience}
payload: ${JSON.stringify(payload)}`
  }

  _deleteJWTPayloadKeys (payload) {
    payload = Object.assign({}, payload)
    delete payload.aud
    delete payload.exp
    delete payload.iss
    delete payload.sub
    delete payload.jti

    return payload
  }

  make (subject, audience, payload, expiresIn) {
    payload = this._deleteJWTPayloadKeys(payload)

    const key = this._getKey(subject, audience, payload)
    let token = cache.get(key)
    if (token) {
      return Promise.resolve(token)
    }

    token = jwt.sign(
      payload,
      this.privateKey,
      {
        algorithm: 'RS256',
        audience: audience || 'urn:home-automation/*',
        expiresIn: expiresIn || EXPIRATION_IN_SECONDS, /* default: ten minutes*/
        issuer: this.issuer,
        subject: subject
      }
    )

    return Promise
      .resolve(http({
        url: url.resolve(this.loginUrl, 'tokens'),
        method: 'POST',
        auth: {
          bearer: token
        },
        json: true,
        resolve: 'body'
      }))
      .get('token')
      .tap((token) => cache.set(key, token))
  }

  makeNew (subject, audience, payload, expiresIn) {
    payload = this._deleteJWTPayloadKeys(payload)

    const key = this._getKey(subject, audience, payload)
    cache.del(key)
    return this.make(subject, audience, payload, expiresIn)
  }
}

module.exports = JWTGenerator
