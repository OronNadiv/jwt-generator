const fs = require('fs')
const path = require('path')
const privateKey = fs.readFileSync(path.join(__dirname, 'private_key.pem'))
const JWTGenerator = require('../dist/index')
const nock = require('nock')
const Promise = require('bluebird')
const Chance = require('chance')
const chance = new Chance()

const loginUrl = 'http://localhost:3001'
const issuer = 'urn:test/me'

require('chai').should()

describe('Generate token', () => {
  'use strict'
  let token
  let subject
  beforeEach(() => {
    token = chance.string()
    subject = Math.random() > 0.5
      ? chance.string() : ''
    subject = chance.string()
    nock(loginUrl)
      .post('/tokens')
      .once() // keep this once! Tests relay on it.
      .reply(200, {token})
  })

  afterEach(() => {
    nock.cleanAll()
  })

  it('should generate token', () => {
    const jwtGenerator = new JWTGenerator({
      loginUrl,
      privateKey,
      useRetry: true,
      issuer
    })

    return Promise
      .resolve(jwtGenerator.makeToken({subject}))
      .then(token => {
        token.should.eql(token)
      })
  })

  it('should fetch token from cache', () => {
    const jwtGenerator = new JWTGenerator({loginUrl, privateKey, useRetry: false})

    return Promise
      .resolve(jwtGenerator.makeToken({subject}))
      .then(token => {
        token.should.eql(token)
        return Promise
          .resolve(jwtGenerator.makeToken({subject}))
          .then(token => {
            token.should.eql(token)
          })
      })
  })

  it('should generate new token', () => {
    const jwtGenerator = new JWTGenerator({loginUrl, privateKey, useRetry: true, issuer})

    return Promise
      .resolve(jwtGenerator.makeNewToken({subject}))
      .then(token => {
        token.should.eql(token)
      })
  })

  it('should generate new token with retry', () => {
    nock.cleanAll()
    const jwtGenerator = new JWTGenerator({loginUrl, privateKey, useRetry: true, issuer})

    nock(loginUrl)
      .post('/tokens')
      .once()
      .reply(500)

    nock(loginUrl)
      .post('/tokens')
      .once()
      .reply(200, {token: token})

    return Promise
      .resolve(jwtGenerator.makeNewToken({subject}))
      .then(token => {
        token.should.eql(token)
      })
  })

  it('should generate token for machine', () => {
    const jwtGenerator = new JWTGenerator({loginUrl, privateKey, useRetry: true})

    return Promise
      .resolve(jwtGenerator.makeNewToken({subject}))
      .then(token => {
        token.should.eql(token)
      })
  })
})
