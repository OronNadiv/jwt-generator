const fs = require('fs')
const path = require('path')
const privateKey = fs.readFileSync(path.join(__dirname, 'private_key.pem'))
const JWTGenerator = require('../src/index')
const nock = require('nock')
const Promise = require('bluebird')
const Chance = require('chance')
const chance = new Chance()

require('chai').should()

describe('Generate token', () => {
  let token
  let subject

  beforeEach(() => {
    token = chance.string()
    subject = Math.random() > 0.5
      ? chance.string() : ''
    subject = chance.string()
    nock('http://localhost:3001')
      .post('/tokens')
      .once() // keep this once! Tests relay on it.
      .reply(200, {token})
  })

  afterEach(() => {
    nock.cleanAll()
  })

  it('should generate token', () => {
    const jwtGenerator = new JWTGenerator('http://localhost:3001', privateKey, true, 'urn:test/me')

    return Promise
      .resolve(jwtGenerator.makeToken(subject))
      .then(token => {
        token.should.eql(token)
      })
  })

  it('should fetch token from cache', () => {
    const jwtGenerator = new JWTGenerator('http://localhost:3001', privateKey, false, 'urn:test/me')

    return Promise
      .resolve(jwtGenerator.makeToken(subject))
      .then(token => {
        token.should.eql(token)
        return Promise
          .resolve(jwtGenerator.makeToken(subject))
          .then(token => {
            token.should.eql(token)
          })
      })
  })

  it('should generate new token', () => {
    const jwtGenerator = new JWTGenerator('http://localhost:3001', privateKey, true, 'urn:test/me')

    return Promise
      .resolve(jwtGenerator.makeNewToken(subject))
      .then(token => {
        token.should.eql(token)
      })
  })

  it('should generate new token with retry', () => {
    nock.cleanAll()
    const jwtGenerator = new JWTGenerator('http://localhost:3001', privateKey, true, 'urn:test/me')

    nock('http://localhost:3001')
      .post('/tokens')
      .once()
      .reply(500)

    nock('http://localhost:3001')
      .post('/tokens')
      .once()
      .reply(200, {token: token})

    return Promise
      .resolve(jwtGenerator.makeNewToken(subject))
      .then(token => {
        token.should.eql(token)
      })
  })

  it('should generate token for machine', () => {
    const jwtGenerator = new JWTGenerator('http://localhost:3001', privateKey, true)

    return Promise
      .resolve(jwtGenerator.makeNewToken(subject))
      .then(token => {
        token.should.eql(token)
      })
  })
})
