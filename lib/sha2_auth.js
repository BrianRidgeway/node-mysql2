'use strict';

const myCrypto = require('./utils/crypto.js');

function generateSha2FastToken(password, nonce) {
  let passwordBuffer = Buffer.from(password, 'ascii');

  const authToken = myCrypto.xor(
    myCrypto.sha256(myCrypto.sha256(myCrypto.sha256(passwordBuffer)), nonce),
    myCrypto.sha256(passwordBuffer)
  );
  return authToken;
}

function generateSha256Token(password, nonce, serverPublicKey) {
  const authToken = myCrypto.xor(password, nonce);
  return myCrypto.encrypt(authToken, serverPublicKey);
}

module.exports = {
  generateSha2FastToken: generateSha2FastToken,
  generateSha256Token: generateSha256Token
};
