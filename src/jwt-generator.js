const EXPIRATION_IN_SECONDS = 300
const jwt = require('jsonwebtoken')
const Promise = require('bluebird')
const http = require('http-as-promised')
const url = require('url')
const Joi = require('joi-browser')

const cacheOptions = {
  max: 10,
  maxAge: Math.floor(EXPIRATION_IN_SECONDS * 1000 * 0.9),
  maxElements: 1000
}

const cache = require('lru-cache')(cacheOptions)

const schemaGetKey = Joi.object().keys({
  subject: Joi.string().required(),
  audience: Joi.string().required(),
  payload: Joi.any().required(),
  issuer: Joi.string().required(),
  loginUrl: Joi.string().required(),
  privateKey: Joi.string().required()
})
const getKey = (options) => {
  Joi.validate(options, schemaGetKey)
  const {subject, audience, payload, issuer, loginUrl, privateKey} = options

  return `issuer: ${issuer}
loginUrl: ${loginUrl}
privateKey: ${privateKey}
subject: ${subject}
audience: ${audience}
payload: ${JSON.stringify(payload)}`
}

const deleteJWTPayloadKeys = (payload) => {
  payload = Object.assign({}, payload)
  delete payload.iss
  delete payload.sub
  delete payload.aud
  delete payload.exp
  delete payload.nbf
  delete payload.iat
  delete payload.jti

  return payload
}

const getSubject = (subject) => {
  return subject ? JSON.stringify(subject) : subject
}

class JWTGenerator {
  constructor (loginUrl, privateKey, issuer) {
    this.issuer = issuer
    this.loginUrl = loginUrl
    this.privateKey = privateKey
  }

  make ({subject, audience, payload, expiresIn}) {
    subject = getSubject(subject)
    payload = deleteJWTPayloadKeys(payload)

    const key = getKey({
      subject,
      audience,
      payload,
      issuer: this.issuer,
      loginUrl: this.loginUrl,
      privateKey: this.privateKey
    })
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
        expiresIn: expiresIn || EXPIRATION_IN_SECONDS, /* default: ten minutes */
        issuer: this.issuer,
        subject
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

  makeNew ({subject, audience, payload, expiresIn}) {
    subject = getSubject(subject)
    payload = deleteJWTPayloadKeys(payload)

    const key = getKey({
      subject,
      audience,
      payload,
      issuer: this.issuer,
      loginUrl: this.loginUrl,
      privateKey: this.privateKey
    })
    cache.del(key)
    return this.make({subject, audience, payload, expiresIn})
  }
}

module.exports = JWTGenerator
