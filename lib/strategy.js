/*
  This module authenticates via an OAuth-like strategy with credentials that are the app name and a client token (which are provided by devmtn), a callbackURL, and the json web token secret. It will redirect to devmounta.in for user login, which will return a json web token to the callback. To verify the token is valid on the app's server, app must also have the json web token secret (also provided by devmtn).

*/
var inherits = require('inherits');
var Strategy = require('passport-strategy');
var OAuth2 = require('oauth').OAuth2;

function DevmtnStrategy (options, verify) {

  if (typeof options == 'function') {
    verify = options;
    options = undefined;
  }
  options = options || {};

  if (!options.app) { throw new TypeError('DevmtnStrategy requires an app credential'); }
  if (!options.client_token) { throw new TypeError('DevmtnStrategy requires a client_token credential'); }
  if (!options.callbackURL) { throw new TypeError('DevmtnStrategy requires a callbackURL'); }
  if (!options.jwtSecret) { throw new TypeError('DevmtnStrategy requires a jwtSecret'); }
  if (typeof verify !== 'function' || !verify) {
    throw new TypeError('Requires a verify callback')
  }

  Strategy.call(this);
  this.name = 'devmtn',
  this._app = options.app;
  this._redirect_uri = options.callbackURL;
  this._callbackURL = options.callbackURL
  this._jwtSecret = options.jwtSecret;
  this._verify = verify;
  options.authorizationURL = 'http://devmounta.in/login';



   this._oauth2 = new OAuth2(options.client_token,  '',
      '', options.authorizationURL, '', '');
}

inherits(DevmtnStrategy, Strategy);

DevmtnStrategy.prototype.authenticate = function(req, options, next) {
  options = options || {};
  var user = {};
  var self = this;

  if (req.query && req.query.error) {
    return this.fail({message: 'access_denied'})
  }

  if (req.query && req.query.token) {
    var jwt = require('jsonwebtoken');
      var jwtoken = req.query.token;

          //verify secret and check expiration
    jwt.verify(jwtoken, this._jwtSecret, function(err, decoded) {
      if (err) {
        console.log(err);
        if (req.session.decoded) { delete req.session.decoded; }
        // TODO return error
        return self.fail({message: 'jwtoken secret does not match.'})

      } else {
        //token is valid, update decoded
        user = decoded;


      function verified(err, user, info) {
            if (err) { return self.error(err); }
            if (!user) { return self.fail(info); }
            return self.success(user, info);
          }
          try {
            if (self._passReqToCallback) {
              var arity = self._verify.length;
              if (arity == 4) {
                self._verify(req, params, user, verified);
              } else { // arity == 3
                self._verify(req, user, verified);
              }
            } else {
              var arity = self._verify.length;
              if (arity == 3) {
                self._verify(params, user, verified);
              } else { // arity == 2
                self._verify(user, verified);
              }
            }
          } catch (ex) {
            return self.error(ex);
          }
                }
    })
  } else {
    var params = {};
    params['bounce'] = this._app;
    params['redirect_uri'] = this._redirect_uri;
    var location = this._oauth2.getAuthorizeUrl(params);
    this.redirect(location);

  }

}

DevmtnStrategy.checkRoles = function(user, checkRole) {
    hasRole = false;
    user.roles.forEach(function(role) {
      if (role.role === checkRole) { hasRole = true; }
    })
    return hasRole;
}

module.exports = DevmtnStrategy
