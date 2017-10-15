const debug = require('debug')('ha:jwt:jwt-generator:debug')
const error = require('debug')('ha:jwt:jwt-generator:error')

const JWTGenerator = require('./jwt-generator')
const Promise = require('bluebird')
const retry = require('bluebird-retry')
const getMac = Promise.promisify(require('getmac').getMac)

let _mac

module.exports = class {
  constructor ({loginUrl, privateKey, useRetry, issuer}) {
    debug('constructor called.',
      'loginUrl:', loginUrl,
      'privateKey:', !!privateKey,
      'useRetry:', useRetry,
      'issuer:', issuer)
    this.loginUrl = loginUrl
    this.privateKey = privateKey
    this.issuer = issuer
    this.useRetry = useRetry === true
  }

  _make ({loginUrl, privateKey, issuer, useRetry, generatorFunc}) {
    const self = this
    const promiseFunc = () => {
      debug('promiseFunc called.')
      return Promise
        .resolve(_mac || getMac())
        .then(mac => {
          debug(`mac: ${mac}`)
          _mac = mac
          self._jwtGenerator = self._jwtGenerator || new JWTGenerator(loginUrl, privateKey, issuer || `urn:mac://${_mac}`)
          return generatorFunc(self._jwtGenerator, _mac)
        })
        .catch(err => {
          error('error in _make.',
            'err:', err)
          throw err
        })
    }

    debug('_make called.',
      'loginUrl:', loginUrl,
      'privateKey:', !!privateKey,
      'issuer:', issuer,
      'generatorFunc:', !!generatorFunc,
      'useRetry:', useRetry)

    return useRetry ? retry(promiseFunc, {max_tries: -1}) : promiseFunc()
  }

  makeToken ({subject, audience, payload, expiresIn}) {
    debug('makeToken called.',
      'subject:', subject,
      'audience:', audience,
      'payload:', payload,
      'expiresIn:', expiresIn)

    return this._make({
      loginUrl: this.loginUrl,
      privateKey: this.privateKey,
      issuer: this.issuer,
      useRetry: this.useRetry,
      generatorFunc: (jwtGenerator, mac) => {
        return jwtGenerator.make({
          subject: subject || mac,
          audience,
          payload: payload || {mac},
          expiresIn
        })
      }
    })
  }

  makeNewToken ({subject, audience, payload, expiresIn}) {
    debug('makeNewToken called.',
      'subject:', subject,
      'audience:', audience,
      'payload:', payload,
      'expiresIn:', expiresIn)

    return this._make({
      loginUrl: this.loginUrl,
      privateKey: this.privateKey,
      issuer: this.issuer,
      useRetry: this.useRetry,
      generatorFunc: (jwtGenerator, mac) => {
        return jwtGenerator.makeNew({
          subject: subject || mac,
          audience,
          payload: payload || {mac},
          expiresIn
        })
      }
    })
  }
}
