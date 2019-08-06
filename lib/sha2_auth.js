'use strict';

const xor = require('./utils/crypto.js').xor;
const sha256 = require('./utils/crypto.js').sha256;
const encrypt = require('./utils/crypto.js').encrypt;

function generateSha2FastToken(password, nonce) {
  const passwordBuffer = Buffer.from(password, 'ascii');

  const authToken = xor(
    sha256(sha256(sha256(passwordBuffer)), nonce),
    sha256(passwordBuffer)
  );
  return authToken;
}

function generateSha256Token(password, nonce, serverPublicKey) {
  const authToken = xor(password, nonce);
  return encrypt(authToken, serverPublicKey);
}

function isPublicRsaKey(buffer) {
  // FIXME better way to test for valid public key?
  return (
    buffer.length > 0 && buffer.toString('ascii').match('BEGIN PUBLIC KEY')
  );
}

module.exports = {
  generateSha2FastToken,
  generateSha256Token,
  isPublicRsaKey
};
