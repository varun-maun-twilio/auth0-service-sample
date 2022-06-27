
var jwksClient = require('jwks-rsa');
var jwt = require('jsonwebtoken');

 
async function validateToken(token){

    var jswksClient = jwksClient({
        jwksUri:process.env.AUTH0_JWKS_URI
      });

    function getKey(header, callback){
        jswksClient.getSigningKey(header.kid, function(err, key) {
          var signingKey = key.publicKey || key.rsaPublicKey;
          callback(null, signingKey);
        });
      }
     
     const decodedToken = await new Promise(function(resolve, reject) {
      jwt.verify(token, getKey, {}, function(err, decoded) {
        if (err !== null) reject(err);
        else resolve(decoded);
        });
     }).catch(e=>null);

   return decodedToken!=null 
}

exports.handler = async function(context, event, callback) {
    const response = new Twilio.Response();
    response.appendHeader('Access-Control-Allow-Origin', '*');
    response.appendHeader('Access-Control-Allow-Methods', 'OPTIONS POST GET');
    response.appendHeader('Access-Control-Allow-Headers', 'Content-Type');
    response.appendHeader('Content-Type', 'application/json');
  
    let token = null;
    let authHeader = event.request.headers.authorization || '';
    if (authHeader.startsWith("Bearer ")){
        token = authHeader.substring(7, authHeader.length);
    }

    //Check if token valid
    if(token==null || ! await validateToken(token)){
        response.setBody({    
            statusCode: 400,
            errorMessage:'Token missing or invalid'
          });
          return callback(null, response);
    }


    response.setBody({    
        statusCode: 200
    });
    return callback(null, response);
  };
  