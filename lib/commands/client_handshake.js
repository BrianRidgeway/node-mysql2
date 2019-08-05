'use strict';

const Command = require('./command.js');
const Packets = require('../packets/index.js');
const ClientConstants = require('../constants/client.js');
const CharsetToEncoding = require('../constants/charset_encodings.js');
const auth41 = require('../auth_41.js');
const crypto = require('crypto');

function flagNames(flags) {
  const res = [];
  for (const c in ClientConstants) {
    if (flags & ClientConstants[c]) {
      res.push(c.replace(/_/g, ' ').toLowerCase());
    }
  }
  return res;
}

class ClientHandshake extends Command {
  constructor(clientFlags) {
    super();
    this.handshake = null;
    this.clientFlags = clientFlags;
  }

  start() {
    return ClientHandshake.prototype.handshakeInit;
  }

  sendSSLRequest(connection) {
    const sslRequest = new Packets.SSLRequest(
      this.clientFlags,
      connection.config.charsetNumber
    );
    connection.writePacket(sslRequest.toPacket());
  }

  sendCredentials(connection) {
    if (connection.config.debug) {
      // eslint-disable-next-line
      console.log(
        'Sending handshake packet: flags:%d=(%s)',
        this.clientFlags,
        flagNames(this.clientFlags).join(', ')
      );
    }
    this.user = connection.config.user;
    this.password = connection.config.password;
    this.passwordSha1 = connection.config.passwordSha1;
    this.database = connection.config.database;
    const handshakeResponse = new Packets.HandshakeResponse({
      flags: this.clientFlags,
      user: this.user,
      database: this.database,
      password: this.password,
      passwordSha1: this.passwordSha1,
      charsetNumber: connection.config.charsetNumber,
      authPluginData1: this.handshake.authPluginData1,
      authPluginData2: this.handshake.authPluginData2,
      compress: connection.config.compress,
      connectAttributes: connection.config.connectAttributes
    });
    connection.writePacket(handshakeResponse.toPacket());
  }
  calculateCachingSha2PasswordAuthToken(scramble) {
    const authToken = auth41.calculateSha2FastToken(this.password, scramble);
    return authToken;
  }
  calculateNativePasswordAuthToken(authPluginData) {
    // TODO: dont split into authPluginData1 and authPluginData2, instead join when 1 & 2 received
    const authPluginData1 = authPluginData.slice(0, 8);
    const authPluginData2 = authPluginData.slice(8, 20);
    let authToken;
    if (this.passwordSha1) {
      authToken = auth41.calculateTokenFromPasswordSha(
        this.passwordSha1,
        authPluginData1,
        authPluginData2
      );
    } else {
      authToken = auth41.calculateToken(
        this.password,
        authPluginData1,
        authPluginData2
      );
    }
    return authToken;
  }
  calculateSha256PasswordAuthToken(serverScramble) {
    const authToken = auth41.xor(
      Buffer.from(this.password + '\0', 'ascii'),
      serverScramble
    );
    return authToken;
  }

  handshakeInit(helloPacket, connection) {
    this.on('error', e => {
      connection._fatalError = e;
      connection._protocolError = e;
    });
    this.handshake = Packets.Handshake.fromPacket(helloPacket);
    if (connection.config.debug) {
      // eslint-disable-next-line
      console.log(
        'Server hello packet: capability flags:%d=(%s)',
        this.handshake.capabilityFlags,
        flagNames(this.handshake.capabilityFlags).join(', ')
      );
    }
    connection.serverCapabilityFlags = this.handshake.capabilityFlags;
    connection.serverEncoding = CharsetToEncoding[this.handshake.characterSet];
    connection.connectionId = this.handshake.connectionId;
    const serverSSLSupport =
      this.handshake.capabilityFlags & ClientConstants.SSL;
    // use compression only if requested by client and supported by server
    connection.config.compress =
      connection.config.compress &&
      this.handshake.capabilityFlags & ClientConstants.COMPRESS;
    this.clientFlags = this.clientFlags | connection.config.compress;
    if (connection.config.ssl) {
      // client requires SSL but server does not support it
      if (!serverSSLSupport) {
        const err = new Error('Server does not support secure connnection');
        err.code = 'HANDSHAKE_NO_SSL_SUPPORT';
        err.fatal = true;
        this.emit('error', err);
        return false;
      }
      // send ssl upgrade request and immediately upgrade connection to secure
      this.clientFlags |= ClientConstants.SSL;
      this.sendSSLRequest(connection);
      connection.startTLS(err => {
        // after connection is secure
        if (err) {
          // SSL negotiation error are fatal
          err.code = 'HANDSHAKE_SSL_ERROR';
          err.fatal = true;
          this.emit('error', err);
          return;
        }
        // rest of communication is encrypted
        this.sendCredentials(connection);
      });
    } else {
      this.sendCredentials(connection);
    }
    return ClientHandshake.prototype.handshakeResult;
  }
  rsaEncrypt(message, key) {
    const encryptedMessage = crypto.publicEncrypt(
      {
        key: key,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
      },
      message
    );
    return encryptedMessage;
  }
  scramble(message, scramble) {
    let scrambledMessage = message;
    for (var i = 0; i < message.length; i++) {
      message[i] ^= scramble[i % scramble.length];
    }
    return message;
  }
  handshakeResult(packet, connection) {
    const marker = packet.peekByte();
    if (marker === 0xfe || marker === 1) {
      let asr, asrmd;
      const authSwitchHandlerParams = {};
      if (marker === 1) {
        asrmd = Packets.AuthSwitchRequestMoreData.fromPacket(packet);
        authSwitchHandlerParams.pluginData = asrmd.data;
      } else {
        asr = Packets.AuthSwitchRequest.fromPacket(packet);
        authSwitchHandlerParams.pluginName = asr.pluginName;
        authSwitchHandlerParams.pluginData = asr.pluginData;
      }
      if (authSwitchHandlerParams.pluginName === 'mysql_native_password') {
        const authToken = this.calculateNativePasswordAuthToken(
          authSwitchHandlerParams.pluginData
        );
        connection.writePacket(
          new Packets.AuthSwitchResponse(authToken).toPacket()
        );
      } else if (
        authSwitchHandlerParams.pluginName === 'sha256_password' ||
        (this.authPlugin !== undefined &&
          this.authPlugin.pluginName === 'sha256_password')
      ) {
        if (connection.config.ssl) {
          const authToken =
            connection.config.password + Buffer.from('00', 'hex');
          connection.writePacket(
            new Packets.AuthSwitchResponse(authToken).toPacket()
          );
        } else {
          if (
            connection.config.serverPublicKey === undefined &&
            this.authPlugin === undefined
          ) {
            this.authPlugin = {
              pluginName: authSwitchHandlerParams.pluginName,
              pluginData: authSwitchHandlerParams.pluginData
            };
            connection.writePacket(
              new Packets.AuthSwitchRequestMoreData(Buffer.from('')).toPacket()
            );
          } else {
            let serverPublicKey, serverScramble;
            if (connection.config.serverPublicKey === undefined) {
              serverPublicKey = authSwitchHandlerParams.pluginData;
              serverScramble = this.authPlugin.pluginData;
            } else {
              serverPublicKey = connection.config.serverPublicKey;
              serverScramble = authSwitchHandlerParams.pluginData;
            }
            const authToken = this.calculateSha256PasswordAuthToken(
              serverScramble
            );
            connection.writePacket(
              new Packets.AuthSwitchResponse(
                this.rsaEncrypt(authToken, serverPublicKey)
              ).toPacket()
            );
          }
        }
      } else if (
        authSwitchHandlerParams.pluginName === 'caching_sha2_password' ||
        (this.authPlugin !== undefined &&
          this.authPlugin.pluginName === 'caching_sha2_password')
      ) {
        if (this.authPlugin === undefined) {
          this.authPlugin = {
            pluginName: authSwitchHandlerParams.pluginName,
            pluginData: authSwitchHandlerParams.pluginData
          };
        }
        if (marker === 0xfe) {
          const authToken = this.calculateCachingSha2PasswordAuthToken(
            this.authPlugin.pluginData
          );
          connection.writePacket(
            new Packets.AuthSwitchResponse(authToken).toPacket()
          );
        } else if (
          !(
            marker === 1 &&
            authSwitchHandlerParams.pluginData.toString('hex') === '03'
          )
        ) {
          if (connection.config.ssl || connection.config.socketPath) {
            const authToken = this.password + Buffer.from('00', 'hex');
            connection.writePacket(
              new Packets.AuthSwitchResponse(authToken).toPacket()
            );
          } else {
            if (
              marker === 1 &&
              authSwitchHandlerParams.pluginData
                .toString('ascii')
                .match('BEGIN PUBLIC KEY')
            ) {
              connection.config.serverPublicKey =
                authSwitchHandlerParams.pluginData;
            }
            if (connection.config.serverPublicKey === undefined) {
              connection.writePacket(
                new Packets.AuthSwitchResponse(
                  Buffer.from('02', 'hex')
                ).toPacket()
              ); /*
              connection.writePacket(
                new Packets.AuthSwitchRequestMoreData(Buffer.from( '' )).toPacket()
              );*/
            } else {
              let serverPublicKey, serverScramble;
              if (connection.config.serverPublicKey === undefined) {
                serverPublicKey = authSwitchHandlerParams.pluginData;
                serverScramble = this.authPlugin.pluginData;
              } else {
                serverPublicKey = connection.config.serverPublicKey;
                serverScramble = this.authPlugin.pluginData;
              }
              const authToken = this.calculateSha256PasswordAuthToken(
                serverScramble
              );
              connection.writePacket(
                new Packets.AuthSwitchResponse(
                  this.rsaEncrypt(authToken, serverPublicKey)
                ).toPacket()
              );
            }
          }
        }
      } else if (connection.config.authSwitchHandler) {
        connection.config.authSwitchHandler(
          authSwitchHandlerParams,
          (err, data) => {
            if (err) {
              connection.emit('error', err);
              return;
            }
            connection.writePacket(
              new Packets.AuthSwitchResponse(data).toPacket()
            );
          }
        );
      } else {
        connection.emit(
          'error',
          new Error(
            'Server requires auth switch, but no auth switch handler provided'
          )
        );
        return null;
      }
      return ClientHandshake.prototype.handshakeResult;
    }
    if (marker !== 0) {
      const err = new Error('Unexpected packet during handshake phase');
      if (this.onResult) {
        this.onResult(err);
      } else {
        connection.emit('error', err);
      }
      return null;
    }
    // this should be called from ClientHandshake command only
    // and skipped when called from ChangeUser command
    if (!connection.authorized) {
      connection.authorized = true;
      if (connection.config.compress) {
        const enableCompression = require('../compressed_protocol.js')
          .enableCompression;
        enableCompression(connection);
      }
    }
    if (this.onResult) {
      this.onResult(null);
    }
    return null;
  }
}
module.exports = ClientHandshake;
