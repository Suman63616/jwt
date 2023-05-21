function decode(token) {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid JWT");
  }
  const payload = parts[1];
  return JSON.parse(atob(payload));
}

module.exports = decode;
