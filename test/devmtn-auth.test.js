var expect = require('expect.js');
var Devmtn = require('../lib/index.js');
var DevmtnStrategy = Devmtn.Strategy;

describe('DevmtnStrategy', function() {

  var strategy = new DevmtnStrategy({
    app: 'testApp',
    client_token: '42istheanswertotheultimatequestion',
    callbackURL: 'http://localhost:8034/auth/devmtn/callback',
    jwtSecret: 'ifonlyIknewwhatthequestionwas'
  }, function() {});

  it('should be named devmtn', function() {
    expect(strategy.name).to.equal('devmtn');
  });

  it('should throw if constructed without a verify callback', function() {
    expect(function() {
      new DevmtnStrategy({
        app: 'testApp',
        client_token: '42istheanswertotheultimatequestion',
        callbackURL: 'http://localhost:8034/auth/devmtn/callback',
        jwtSecret: 'ifonlyIknewwhatthequestionwas'
      })
    }).to.throwException(TypeError, 'DevmtnStrategy requires a verify callback');
  })

  it('should throw if constructed without an app credential', function() {
  expect(function() {
    new DevmtnStrategy({
      client_token: '42istheanswertotheultimatequestion',
      callbackURL: 'http://localhost:8034/auth/devmtn/callback',
      jwtSecret: 'ifonlyIknewwhatthequestionwas'
    }, function() {})
  }).to.throwException(TypeError, 'DevmtnStrategy requires an app credential')
})

  it('should throw if constructed without a client_token credential', function() {
      expect(function() {
        new DevmtnStrategy({
          app: 'testApp',
          callbackURL: 'http://localhost:8034/auth/devmtn/callback',
          jwtSecret: 'ifonlyIknewwhatthequestionwas'
        }, function() {})
      }).to.throwException(TypeError, 'DevmtnStrategy requires a client_token credential')
    })

    it('should throw if constructed without a callbackURL', function() {
      expect(function() {
        new DevmtnStrategy({
          app: 'testApp',
          client_token: '42istheanswertotheultimatequestion',
          jwtSecret: 'ifonlyIknewwhatthequestionwas'
        }, function() {})
      }).to.throwException(TypeError, 'DevmtnStrategy requires a callbackURL')
    })

    it('should throw if constructed without a jwtSecret', function() {
      expect(function() {
        new DevmtnStrategy({
          app: 'testApp',
          client_token: '42istheanswertotheultimatequestion',
          callbackURL: 'http://localhost:8034/auth/devmtn/callback'
        }, function() {})
      }).to.throwException(TypeError, 'DevmtnStrategy requires a jwtSecret')
    })

    it('should throw if constructed with only a verify callback', function() {
      expect(function() {
        new DevmtnStrategy(function() {})
      }).to.throwException(TypeError, 'DevmtnStrategy requires an app credential');
    })

})


describe('Devmtn.checkRoles', function() {

  var user = {
    email: 'test@test.com',
    id: 5,
    roles: [{
      role: 'tester',
      id: 1
    },
    {
      role: 'clockmaker',
      id: 3
    }]
  }

  it('should return true if role exists', function() {
    expect(Devmtn.checkRoles(user, 'tester')).to.be(true);
  })

  it('should return false if role does not exist', function() {
    expect(Devmtn.checkRoles(user, 'admin')).to.be(false);
  })


})
