const fs = require('fs')
const path = require('path')
const privateKey = fs.readFileSync(path.join(__dirname, 'private_key.pem'))
const JWTGenerator = require('../src/index')
const nock = require('nock')
const Promise = require('bluebird')

require('should')

describe('Generate token', () => {
  const GENERATED_TOKEN = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpZCI6MSwibmFtZSI6Ik9yb24iLCJpc19hY3RpdmUiOnRydWUsImlzX3RydXN0ZWQiOmZhbHNlLCJpc19hZG1pbiI6ZmFsc2UsImNyZWF0ZWRfYXQiOiIyMDE1LTEyLTIxVDAyOjQ3OjU3LjA2OVoiLCJ1cGRhdGVkX2F0IjoiMjAxNS0xMi0yMVQwMjo0ODowMi40NDBaIiwiaWF0IjoxNDUwODk2MzAzLCJleHAiOjE0NTA4OTY2MDMsImF1ZCI6InVybjpob21lLWF1dG9tYXRpb24vKiIsImlzcyI6InVybjpob21lLWF1dG9tYXRpb24vbG9naW4iLCJzdWIiOiJvcm9uLm5hZGl2QGxhbmV0aXguY29tIn0.grMBdwuRLzESuefGhS1O_nFIIKwOFOc2N8N4KWMireM_zMIKHxqbY0AYwOENKB2NI4Yj06BS27LDGZ29nejx6JW8wH-qjP4_Kl7sgBPuTjNzFkIzqVQSWginmfCTdVY021WFf57UZ7v6gkaXtPWy-FRLiStayzj6qICrG-VkhL4GHlo3aDrAfHljkx7fWRI84ttAr3d9CXdWwjFnCsQClqsQ63VcTD5-BvP0Req8gfuMmOqojvOLUWrUvl36ErR7AbAuWU8RDf3HPr38kWuJMVRQJ1aJ7KNx_odNzVDyLq13H3yVZQonQC47PK4A-bTG8bMCD2IrDErWXcm2O7e47Q'

  beforeEach(() => {
    nock('http://localhost:3001')
      .post('/tokens')
      .once()
      .reply(200, {token: GENERATED_TOKEN})
  })

  afterEach(() => nock.cleanAll())

  it('should generate token', () => {
    const jwtGenerator = new JWTGenerator('http://localhost:3001', privateKey, true, 'urn:test/me')

    return Promise
      .resolve(jwtGenerator.makeToken('1'))
      .then(token => {
        token.should.eql(GENERATED_TOKEN)
      })
  })

  it('should fetch token from cache', () => {
    nock.cleanAll()
    const jwtGenerator = new JWTGenerator('http://localhost:3001', privateKey, false, 'urn:test/me')

    return Promise
      .resolve(jwtGenerator.makeToken('1'))
      .then(token => {
        token.should.eql(GENERATED_TOKEN)
      })
  })

  it('should generate new token', () => {
    const jwtGenerator = new JWTGenerator('http://localhost:3001', privateKey, true, 'urn:test/me')

    return Promise
      .resolve(jwtGenerator.makeNewToken('1'))
      .then(token => {
        token.should.eql(GENERATED_TOKEN)
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
      .reply(200, {token: GENERATED_TOKEN})

    return Promise
      .resolve(jwtGenerator.makeNewToken('1'))
      .then(token => {
        token.should.eql(GENERATED_TOKEN)
      })
  })

  it('should generate token for machine', () => {
    const jwtGenerator = new JWTGenerator('http://localhost:3001', privateKey, true)

    return Promise
      .resolve(jwtGenerator.makeNewToken())
      .then(token => {
        token.should.eql(GENERATED_TOKEN)
      })
  })
})
