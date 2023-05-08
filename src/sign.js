const crypto = require('crypto');


const defaultOptions = {
  expiresIn: 8.64e7,
  algorithm: 'HS256',
};

function createSignature(secret, encodedHeader, encodedPayload, algorithm) {
    if (algorithm === 'HS256') {
      return crypto
        .createHmac('sha256', secret)
        .update(encodedHeader + '.' + encodedPayload)
        .digest('base64');
    } else if (algorithm === 'RS256') {
      const signer = crypto.createSign('RSA-SHA256');
    signer.update(encodedHeader + '.' + encodedPayload);
    return signer.sign(secret, 'base64');
    }
  }

  function sign(payload, secret, options = {}) {
    const mergedOptions = { ...defaultOptions, ...options };
    const header = { alg: mergedOptions.algorithm, typ: 'JWT' };
    const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64');
    const expiresIn = Math.floor(Date.now() / 1000) + mergedOptions.expiresIn;
    const encodedPayload = Buffer.from(JSON.stringify({ ...payload, exp: expiresIn , alg:mergedOptions.algorithm})).toString('base64');
    const signature = createSignature(secret, encodedHeader, encodedPayload, mergedOptions.algorithm);
    return `${encodedHeader}.${encodedPayload}.${signature}`;
  }
  
  module.exports ={ sign,createSignature};