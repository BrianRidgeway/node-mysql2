'use strict';

const crypto = require('crypto');

function createHash(components, options) {
  options = Object.assign({ algorithm: 'sha256' }, options);

  const hash = crypto.createHash(options.algorithm);
  components.forEach(component => hash.update(component));

  return hash.digest();
}

exports.sha256 = function() {
  return createHash(Array.prototype.slice.call(arguments));
};

exports.sha1 = function() {
  return createHash(Array.prototype.slice.call(arguments), {
    algorithm: 'sha1'
  });
};

exports.xor = function(a, b) {
  if (!Buffer.isBuffer(a)) {
    a = Buffer.from(a, 'binary');
  }

  if (!Buffer.isBuffer(b)) {
    b = Buffer.from(b, 'binary');
  }

  const result = Buffer.allocUnsafe(a.length);

  for (let i = 0; i < a.length; i++) {
    result[i] = a[i] ^ b[i % b.length];
  }
  return result;
};

exports.encrypt = function(message, key) {
  const encryptedMessage = crypto.publicEncrypt(
    {
      key: key,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
    },
    message
  );
  return encryptedMessage;
};
