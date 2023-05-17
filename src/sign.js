const crypto = require("crypto");
const timeSpan = require("./timeSpan");

const defaultOptions = {
  expiresIn: 8.64e7,
  algorithm: "HS256",
};

function createSignature(secret, encodedHeader, encodedPayload, algorithm) {
  if (algorithm === "HS256") {
    return crypto
      .createHmac("sha256", secret)
      .update(encodedHeader + "." + encodedPayload)
      .digest("base64");
  } else if (algorithm === "RS256") {
    const signer = crypto.createSign("RSA-SHA256");
    signer.update(encodedHeader + "." + encodedPayload);
    return signer.sign(secret, "base64");
  } else if (algorithm === "ES256") {
    const signer = crypto.createSign("sha256");
    signer.update(encodedHeader + "." + encodedPayload);
    return signer.sign(secret, "base64");
  } else {
    throw new Error("Unsupported algorithm");
  }
}

function sign(payload, secret, options = {}) {
  try {
    const mergedOptions = { ...defaultOptions, ...options };
    const header = { alg: mergedOptions.algorithm, typ: "JWT" };
    const encodedHeader = Buffer.from(JSON.stringify(header)).toString(
      "base64"
    );

    mergedOptions.expiresIn = timeSpan(mergedOptions.expiresIn);

    const expiresIn = mergedOptions.expiresIn;
    const encodedPayload = Buffer.from(
      JSON.stringify({
        ...payload,
        exp: expiresIn,
        alg: mergedOptions.algorithm,
      })
    ).toString("base64");
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
