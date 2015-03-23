var CelfinetSingleSignOnStrategy = require('./strategy/celfinetSingleSignOnStrategyProvider').Strategy  
  , querystring = require('querystring')
  , request = require('request')
  , config = require('./config/config');


module.exports = function (passport) {
  
  // serialize sessions
  passport.serializeUser(function(user, done) {
    done(null, user)
  });

  passport.deserializeUser(function(user, done) {
    done(null, user)  
  });

  // Custom strategy
  passport.use(new CelfinetSingleSignOnStrategy(
    function(username, password, done) {      
      var locals = {};

      if(username === '' || password === '') {        
        done(null, false)
      }

      var postData = querystring.stringify({
        grant_type: 'password',
        username: username,
        password: password
      });

      var contentLength = postData.length;

      var options = {
        uri: config.authorizationHostName + '/SharedServices/token',
        body: postData,
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': contentLength,
          'Application': config.applicationID
        }
      };

      request(options, function (err, result, bodyRes) {
        if(err) {
          return done(err);
        }

        if(result.statusCode === 500) {
          return done(true);
        }

        var user = JSON.parse(bodyRes);

        if(typeof user.error !== 'undefined') {                                
          return done(null, false);
        }

        return done(null, user);
      });
    }
  ));
}