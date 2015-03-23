/**********************************\
|Controller for User Authentication|
\**********************************/
var moment = require('moment')
	, request = require('request')
	, config = require('./config/config');

/* Authenticates user on login */
exports.userAuthentication = userAuthentication;
function userAuthentication(passport) {
	passport.authenticate('celfinetSingleSignOn', function(err, user) {		    
	    if (err) { 
	    	var message = 'Something went wrong while processing the login information. Contact the administrator for more info.';
	    	var resultObj = {auth: false, message: message};
	    	return resultObj;
	    }
	    
	    if (!user) { 
	    	var message = 'The username or password provided are incorrect.'
	    	var resultObj = {auth: false, message: message};
	    	return resultObj;
	    }

	    /* 
	    	Since req is not available the session timer will be handled here and will be returned to the application
			alongside the user object
	     */
	   	var issuedDate = moment(new Date(user[".issued"]));
	    var expireDate = moment(new Date(user[".expires"]));

	    var sessionTime = expireDate.valueOf() - issuedDate.valueOf();

	    var resultObj = {auth: true, message: '', user: user, sessionTime: sessionTime};
	    return resultObj;

	    /*req.logIn(user, function(err) {
	      	if (err) { 
	      		return next(err); 
	      	}

	      	var issuedDate = moment(new Date(req.user[".issued"]));
	      	var expireDate = moment(new Date(req.user[".expires"]));

	      	var millisecondsToSessionExpire = expireDate.valueOf() - issuedDate.valueOf();

	      	req.session.cookie.maxAge = millisecondsToSessionExpire;

	      	return res.redirect('/');
	    });*/
	});	
}

/* Logs the user out of the application */
exports.logoutUser = function(tokenType, accessToken) {

	var authorization = tokenType + ' ' + accessToken;

	var options = {
        uri: config.authorizationHostName + '/SharedServices/api/account/logout',        
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Application': config.applicationID,
          'Authorization': authorization
        }
    };

    request(options, function (err, result, bodyRes) {
        if(result.statusCode !== 200) {
        	return false;
        }

        return true;
    });	
}