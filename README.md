# Home Automation - JSON Web Token (JWT) Generator
This package is being used by the [home automation project][overview-url].
The package generates 'JSON Web Token' [(JWT)][jwt-url] by using the API of the [authentication][auth-url] server.
  
[![NPM version][npm-image]][npm-url]
[![Build Status][travis-image]][travis-url]
[![Test Coverage][coveralls-image]][coveralls-url]
[![Dependencies][dependencies-image]][dependencies-url]
[![DevDependencies][dependencies-dev-image]][dependencies-dev-url]
[![JavaScript Style Guide][standard-image]][standard-url]

## Installation (via [npm](https://www.npmjs.com/package/jwt-generator))

```bash
$ npm install --save jwt-generator
```

## Usage

The package supports ES5 or later.  The example below is using ES6 features.  
[Here][private-public-keys-url] you can find instructions on how to generate private & public keys.

```javascript
const JWTGenerator = require('jwt-generator')

// const jwtGenerator = new JWTGenerator(<url>, <privateKey>, <use retry>, <issuer>)
const jwtGenerator = new JWTGenerator('https://auth.domain.com', <privateKey>, true, 'urn:home-automation/garage-door-raspberry-client')

// jwtGenerator.makeNewToken(<subject>, <audience>, <payload>, <expires (seconds)>)
jwtGenerator.makeNewToken('report garage door state', 'urn:home-automation/garage-door-api', {"name": "John Doe", "admin": true}, 60)
  .then((token) => {
    // JWT generated by the authentication server.
  })

// jwtGenerator.makeToken(<subject>, <audience>, <payload>, <expires (seconds)>)
jwtGenerator.makeToken('report garage door state', 'urn:home-automation/garage-door-api', {"name": "John Doe", "admin": true}, 60)
.then((token) => {
  // JWT generated by the authentication server.
})

```

The difference between `makeToken` and `makeNewToken` is that the former may re-use existing token that has been stored in the cached,
while the latter will always generate new token by calling the [authentication][auth-url] server.

### License
[AGPL-3.0](https://spdx.org/licenses/AGPL-3.0.html)

### Author
[Oron Nadiv](https://github.com/OronNadiv) ([oron@nadiv.us](mailto:oron@nadiv.us))

[dependencies-image]: https://david-dm.org/OronNadiv/jwt-generator/status.svg
[dependencies-url]: https://david-dm.org/OronNadiv/jwt-generator
[dependencies-dev-image]: https://david-dm.org/OronNadiv/jwt-generator/dev-status.svg
[dependencies-dev-url]: https://david-dm.org/OronNadiv/jwt-generator?type=dev
[travis-image]: http://img.shields.io/travis/OronNadiv/jwt-generator.svg?style=flat-square
[travis-url]: https://travis-ci.org/OronNadiv/jwt-generator
[coveralls-image]: http://img.shields.io/coveralls/OronNadiv/jwt-generator.svg?style=flat-square
[coveralls-url]: https://coveralls.io/r/OronNadiv/jwt-generator
[standard-image]: https://img.shields.io/badge/code%20style-standard-brightgreen.svg
[standard-url]: http://standardjs.com
[npm-image]: https://badge.fury.io/js/jwt-generator.svg
[npm-url]: http://badge.fury.io/js/jwt-generator

[jwt-url]: https://jwt.io
[overview-url]: https://oronnadiv.github.io/home-automation
[client-installation-instruction-url]: https://oronnadiv.github.io/home-automation/#installation-instructions-for-the-raspberry-pi-clients
[server-installation-instruction-url]: https://oronnadiv.github.io/home-automation/#installation-instructions-for-the-server-micro-services
[private-public-keys-url]: https://oronnadiv.github.io/home-automation/#generating-private-and-public-keys

[alarm-url]: https://github.com/OronNadiv/alarm-system-api
[auth-url]: https://github.com/OronNadiv/authentication-api
[camera-url]: https://github.com/OronNadiv/camera-api
[garage-url]: https://github.com/OronNadiv/garage-door-api
[notifications-url]: https://github.com/OronNadiv/notifications-api
[push-url]: https://github.com/OronNadiv/push-api
[storage-url]: https://github.com/OronNadiv/storage-api
[ui-url]: https://github.com/OronNadiv/home-automation-ui
