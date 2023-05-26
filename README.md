# Installation
```bash 
 $ npm install jsonwebtoken-lib
```

# Usage

### jwt.sign(payload, secretOrPrivateKey, [options, callback])


# Import in node.js file
```js
const jwt = require('jsonwebtoken-lib')
         //or
import jwt from ('jsonwebtoken-lib')
```

---must specify the algorithm as 'HS256' for Symmetric and 'RS256' or 'ES256' for asymmetric in options.

jwt.sign(payload, secretOrPrivateKey, {options})
secretOrPrivateKey is a string (utf-8 encoded), buffer, object, or KeyObject containing either the secret for HMAC algorithms or the PEM encoded private key for RSA and ECDSA. In case of a private key with passphrase an object { key, passphrase } can be used (based on crypto documentation), in this case be sure you pass the algorithm. When signing with RSA algorithms the minimum modulus length is 2048 except when the allowInsecureKeySizes option is set to true. Private keys below this size will be rejected with an error.

# Sign with (HMAC SHA256)
```js
const jwt = require('jsonwebtoken-lib');
var token = jwt.sign({name: 'suman' }, 'secret',{ expiresIn : '15m',algorithm:'HS256'});
```

# sign with RSA SHA256 
```js
const jwt = require('jsonwebtoken-lib');
var privateKey = fs.readFileSync('private.key');// get private key should be pem file
var token = jwt.sign({ name: 'suman' }, privateKey, { expiresIn : '15m',algorithm:'RS256'});
```

# sign with  ES256 
```js
const jwt = require('jsonwebtoken-lib');
var privateKey = fs.readFileSync('private.key');// get private key should be pem file
var token = jwt.sign({ name: 'suman' }, privateKey, { expiresIn : '15m',algorithm:'ES256'});
```

# verify a token symmetric
```js
jwt.verify(token, 'secret',function(err, decoded) {
  console.log(decoded.name) // suman
});
```

# verify a token asymmetric
```js
var publickey = fs.readFileSync('public.key');  // get public key should be pem file
jwt.verify(token, publickey,function(err, decoded) {
  console.log(decoded.name) // suman
});
```