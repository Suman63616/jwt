const crypto = require('crypto');
const decode = require('./decode');
const { createSignature } = require('./sign');

function dateInPast(exp) {
  const currentDate = Math.floor(Date.now() / 1000);
  return currentDate > exp;
}

function verify(token, secret, callback) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid token');
    }

    const decoded = decode(token);
    const alg = decoded.alg;
    if (alg === 'RS256') {
      const [encodedHeader, encodedPayload, signature] = parts;
      const verifier = crypto.createVerify('RSA-SHA256');
      verifier.update(encodedHeader + '.' + encodedPayload);
      if (!verifier.verify(secret, signature, 'base64')) {
        throw new Error('Invalid signature');
      }
    } else if (alg === 'HS256') {
      const [encodedHeader, encodedPayload, signature] = parts;
      const candidateSignature = createSignature(
        secret,
        encodedHeader,
        encodedPayload,
        alg
      );
      if (signature !== candidateSignature) {
        throw new Error('Invalid signature');
      }
    } else if (alg === 'ES256') {
      const [encodedHeader, encodedPayload, signature] = parts;
      const verifier = crypto.createVerify('SHA256');
      verifier.update(encodedHeader + '.' + encodedPayload);
      if (!verifier.verify({ key: secret, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, signature, 'base64')) {
        throw new Error('Invalid signature');
      }
    } else {
      throw new Error('Unsupported algorithm:');
    }

    const exp = decoded.exp;
    if (dateInPast(exp)) {
      throw new Error('Token has expired');
    }
    callback(null, decoded);
  } catch (error) {
    callback(error, false);
  }
}

module.exports = verify;