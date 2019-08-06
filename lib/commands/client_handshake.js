'use strict';

const Command = require('./command.js');
const Packets = require('../packets/index.js');
const ClientConstants = require('../constants/client.js');
const CharsetToEncoding = require('../constants/charset_encodings.js');
const auth41 = require('../auth_41.js');
const sha2Auth = require('../sha2_auth.js');

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

  shouldUseSha256PasswordAuthPlugin(authParams) {
    return (
      authParams.pluginName === 'sha256_password' ||
      (this.authPlugin !== undefined &&
        this.authPlugin.pluginName === 'sha256_password')
    );
  }

  shouldUseSha2PasswordAuthPlugin(authParams) {
    return (
      authParams.pluginName === 'caching_sha2_password' ||
      (this.authPlugin !== undefined &&
        this.authPlugin.pluginName === 'caching_sha2_password')
    );
  }

  isReceivingServerPublicKey(connection) {
    if (
      this.authPlugin.packetMarker === 1 &&
      sha2Auth.isPublicRsaKey(this.authPlugin.pluginMoreData)
    ) {
      if (
        connection.config.rsa !== undefined &&
        connection.config.rsa.serverPublicKey !== undefined
      ) {
      }
      if (connection.config.debug) {
        console.log('receiving public key from the server');
      }
      connection.config.rsa = {
        serverPublicKey: this.authPlugin.pluginMoreData
      };
      return true;
    }
    return false;
  }
  shouldUseSha2FastAuth() {
    return (
      this.authPlugin !== undefined &&
      this.authPlugin.packetMarker === 0xfe &&
      this.authPlugin.pluginName === 'caching_sha2_password'
    );
  }
  shouldUseSha2FullAuth() {
    return (
      this.authPlugin !== undefined &&
      this.authPlugin.packetMarker === 1 &&
      this.authPlugin.pluginName === 'caching_sha2_password'
    );
  }
  sha2FastAuthPassed() {
    return (
      this.authPlugin !== undefined &&
      this.authPlugin.pluginName === 'caching_sha2_password' &&
      this.authPlugin.packetMarker === 1 &&
      this.authPlugin.pluginMoreData.toString('hex') === '03'
    );
  }
  sha2FastAuthFailed() {
    return (
      this.authPlugin !== undefined &&
      this.authPlugin.pluginName === 'caching_sha2_password' &&
      this.authPlugin.packetMarker === 1 &&
      this.authPlugin.pluginMoreData.toString('hex') == '04'
    );
  }

  hasAnEmptyPassword() {
    return this.password === undefined || this.password.length === 0;
  }
  sendEmptyPassword(connection) {
    if (connection.config.debug) {
      console.log('empty password, skipping all hashing and encrypting');
    }
    connection.writeAuthSwitchResponsePacket('');
  }
  sendPasswordOnSecureConnection(connection) {
    const authToken = this.password + '\0';
    connection.writeAuthSwitchResponsePacket(authToken);
  }

  setAuthPlugin(marker, params) {
    if (marker === 1) {
      this.authPlugin.packetMarker = marker;
      this.authPlugin.pluginMoreData = params.pluginData;
    } else {
      this.authPlugin = params;
      this.authPlugin.packetMarker = marker;
    }
  }

  handleSha2PasswordAuth(connection, packetMarker, authParams) {
    this.setAuthPlugin(packetMarker, authParams);

    if (this.hasAnEmptyPassword()) {
      this.sendEmptyPassword(connection);
    } else if (this.shouldUseSha2FastAuth()) {
      if (connection.config.debug) {
        console.log('attempting sha2 fast authentication');
      }
      const authToken = sha2Auth.generateSha2FastToken(
        this.password,
        this.authPlugin.pluginData.slice(0, 20)
      );
      connection.writeAuthSwitchResponsePacket(authToken);
    } else if (this.sha2FastAuthPassed()) {
      if (connection.config.debug) {
        console.log('sha2 fast authentication successful');
      }
    } else if (this.shouldUseSha2FullAuth()) {
      if (this.sha2FastAuthFailed) {
        if (connection.config.debug) {
          console.log(
            'sha2 fast authentication failed, server is asking for sha2 full authentication'
          );
        }
      }
      if (connection.isSecure()) {
        if (connection.config.debug) {
          console.log('using secure connection for full sha2 authentication');
        }
        this.sendPasswordOnSecureConnection(connection);
      } else {
        if (
          connection.hasServerPublicKey() ||
          this.isReceivingServerPublicKey(connection)
        ) {
          if (connection.config.debug) {
            console.log(
              "using server's public rsa key to encrypt password for sha2 full authentication"
            );
          }
          const authToken = sha2Auth.generateSha256Token(
            this.password + '\0',
            this.authPlugin.pluginData,
            connection.config.rsa.serverPublicKey
          );
          connection.writeAuthSwitchResponsePacket(authToken);
        } else if (connection.canAskForPublicKey()) {
          if (connection.config.debug) {
            console.log(
              "requesting server's public rsa key for sha2 full authentication"
            );
          }
          connection.writeAuthSwitchResponsePacket(Buffer.from('02', 'hex'));
        } else {
          if (connection.config.debug) {
            console.log(
              'No secure methods available to send caching_sha2_password to server'
            );
            console.log(
              'The caching_sha2_password authentication plugin requires an SSL or socket/shared memory connection,  or server RSA keys'
            );
          }
          const err = new Error(
            'Client does not have secure connection available to transmit caching_sha2_password'
          );
          err.fatal = true;
          connection.close();
          this.emit('error', err);
        }
      }
    }
  }

  handleSha256PasswordAuth(connection, packetMarker, authSwitchHandlerParams) {
    this.setAuthPlugin(packetMarker, authSwitchHandlerParams);

    if (this.hasAnEmptyPassword()) {
      this.sendEmptyPassword(connection);
    } else if (connection.isSecure(true)) {
      if (connection.config.debug) {
        console.log(
          'Using sha256_password auth plugin over a secure connection'
        );
      }
      this.sendPasswordOnSecureConnection(connection);
    } else if (
      connection.hasServerPublicKey() ||
      this.isReceivingServerPublicKey(connection)
    ) {
      if (connection.config.debug) {
        console.log(
          'Using sha256_password auth plugin with RSA public encryption'
        );
      }
      const authToken = sha2Auth.generateSha256Token(
        this.password + '\0',
        this.authPlugin.pluginData,
        connection.config.rsa.serverPublicKey
      );
      connection.writeAuthSwitchResponsePacket(authToken);
    } else if (connection.canAskForPublicKey()) {
      if (connection.config.debug) {
        console.log(
          "Requesting server's public key for encryption with sha256_password auth plugin"
        );
      }
      connection.writeAuthSwitchResponsePacket(Buffer.from('01', 'hex'));
    } else {
      if (connection.config.debug) {
        console.log(
          'No secure methods available to send sha256_password to server'
        );
        console.log(
          'The sha256_password authentication plugin requires an SSL connection or server RSA keys'
        );
      }
      const err = new Error(
        'Client does not have secure connection available to transmit sha256_password'
      );
      err.fatal = true;
      connection.close();
      this.emit('error', err);
    }
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
        this.shouldUseSha256PasswordAuthPlugin(authSwitchHandlerParams)
      ) {
        this.handleSha256PasswordAuth(
          connection,
          marker,
          authSwitchHandlerParams
        );
      } else if (
        this.shouldUseSha2PasswordAuthPlugin(authSwitchHandlerParams)
      ) {
        this.handleSha2PasswordAuth(
          connection,
          marker,
          authSwitchHandlerParams
        );
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
