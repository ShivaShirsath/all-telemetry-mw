const { createHash } = require('crypto');
const axios = require('axios');
require('dotenv').config();
envVariables = require('../envVariables');

// Polyfill for jose in Node.js (CommonJS)
if (!globalThis.crypto) {
  const { webcrypto } = require('crypto');
  globalThis.crypto = webcrypto;
}

class JwtAuthGuard {
  constructor() {}

  async checkTokenStatus(user_id, token) {
    try {
      const url = process.env.ALL_ORC_SERVICE_URL;
      const response = await axios.post(url, { user_id, token });
      return {
        isActive: response.data?.result?.isActive ?? false,
      };
    } catch (error) {
      console.error('Error calling token-status API:', error?.response?.data || error.message);
      return { isActive: false };
    }
  }

  async canActivate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ message: 'Authorization header missing' });
    }

    const token = authHeader.split(' ')[1];

    try {
      const { jwtDecrypt, jwtVerify } = await import('jose');

      const secretKey = process.env.JOSE_SECRET;
      const decryptionKey = new Uint8Array(
        createHash('sha256').update(secretKey).digest()
      );

      const { payload: decryptedPayload } = await jwtDecrypt(token, decryptionKey);

      if (!decryptedPayload.jwtSignedToken) {
        return res.status(401).json({ message: 'jwtSignedToken not found in decrypted payload' });
      }

      const jwtSignedToken = String(decryptedPayload.jwtSignedToken);
      const jwtSigninKey = new TextEncoder().encode(process.env.JWT_SIGNIN_PRIVATE_KEY);

      const { payload: verifiedPayload } = await jwtVerify(jwtSignedToken, jwtSigninKey);

      const { isActive } = await this.checkTokenStatus(verifiedPayload.virtual_id, token);
      if (!isActive) {
        return res.status(401).json({ message: 'User is logged out' });
      }

      req.user = verifiedPayload;
      next();
    } catch (err) {
      console.error('JWT error:', err);
      return res.status(401).json({ message: 'Invalid or expired token' });
    }
  }
}

module.exports = new JwtAuthGuard();
