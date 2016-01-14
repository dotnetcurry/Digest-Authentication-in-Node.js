//1.
var http = require('http');
//2.
var crypt = require('crypto');

//3.
var credentials = {
  userName:'mahesh',
  password:'mahesh1234',
  realm:'Digest Authenticatoin'
};
  //3a.
  var hash;
  
 //4. 
  
function cryptoUsingMD5(data) {
  return crypt.createHash('md5').update(data).digest('hex');
}

//5.
hash = cryptoUsingMD5(credentials.realm);
//6.
function authenticateUser(res) {
  console.log({'WWW-Authenticate' : 'Digest realm="' +  credentials.realm + '",qop="auth",nonce="' + Math.random() + '",opaque="' + hash + '"'});
  res.writeHead(401, {'WWW-Authenticate' : 'Digest realm="' +  credentials.realm + '",qop="auth",nonce="' + Math.random() + '",opaque="' + hash + '"'});
  res.end('Authorization is needed.');
}

//7.
function parseAuthenticationInfo(authData) {
  var authenticationObj = {};
  authData.split(', ').forEach(function (d) {
    d = d.split('=');
    
    authenticationObj[d[0]] = d[1].replace(/"/g, '');
  });
  console.log(JSON.stringify(authenticationObj));
  return authenticationObj;
}

//8. 
var server =  http.createServer(function (request, response) {
  var authInfo, digestAuthObject = {};

//9.
  if (!request.headers.authorization) {
    authenticateUser(response);
    return;
  }
  //10.
  authInfo = request.headers.authorization.replace(/^Digest /, '');
  authInfo = parseAuthenticationInfo(authInfo);  
 
 //11.
  if (authInfo.username !==  credentials.userName) 
  {
     authenticateUser(response); return; 
     }
     //12.
  digestAuthObject.ha1 = cryptoUsingMD5(authInfo.username + ':' +  credentials.realm + ':' +  credentials.password);
  //13.
  digestAuthObject.ha2 = cryptoUsingMD5(request.method + ':' + authInfo.uri);
  //14.
  var resp =  cryptoUsingMD5([digestAuthObject.ha1, authInfo.nonce, authInfo.nc, authInfo.cnonce, authInfo.qop,digestAuthObject.ha2].join(':'));
  
  digestAuthObject.response = resp;
  
//15.
  if (authInfo.response !== digestAuthObject.response)
   {
      authenticateUser(response); return; 
      }
      
  response.end('Congratulations!!!! You are successfully authenticated');

});
//16.
server.listen(5050);