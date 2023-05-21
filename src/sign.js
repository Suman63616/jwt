const crypto = require("crypto");
const timeSpan = require("./timeSpan");
const base64url = require('base64url')
const defaultOptions = {
  expiresIn: 8.64e7,
  algorithm: "HS256",
};

function createSignature(secret, encodedHeader, encodedPayload, algorithm) {
  if (algorithm === "HS256") {
    const token= crypto
      .createHmac("sha256", secret)
      .update(encodedHeader + "." + encodedPayload)
      .digest("base64");
      return base64url.fromBase64(token);
  } else if (algorithm === "RS256") {
    const signer = crypto.createSign("RSA-SHA256");
    signer.update(encodedHeader + "." + encodedPayload);
    const signature= signer.sign(secret, "base64");
   return base64url.fromBase64(signature);

  } else if (algorithm === "ES256") {
    const signer = crypto.createSign("sha256");
    signer.update(encodedHeader + "." + encodedPayload);
    const signature= signer.sign(secret, "base64");
   return base64url.fromBase64(signature);
  } else {
    throw new Error("Unsupported algorithm");
  }
}

function sign(payload, secret, options = {}) {
  try {
    const mergedOptions = { ...defaultOptions, ...options };
    const header = { alg: mergedOptions.algorithm, typ: "JWT" };
  
    const encodedHeader = base64url.encode(JSON.stringify(header));

    mergedOptions.expiresIn = timeSpan(mergedOptions.expiresIn);

    const expiresIn = mergedOptions.expiresIn;
   
    const encodedPayload = base64url.encode(JSON.stringify({
      ...payload,
      exp: expiresIn,
      alg: mergedOptions.algorithm,
    }));

    const signature = createSignature(
      secret,
      encodedHeader,
      encodedPayload,
      mergedOptions.algorithm
    );
    return `${encodedHeader}.${encodedPayload}.${signature}`;
  } catch (error) {
    return error;
  }
}

module.exports = { sign, createSignature };
