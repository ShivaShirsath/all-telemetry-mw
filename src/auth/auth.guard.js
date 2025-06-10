const { createHash } = require('crypto');
require('dotenv').config();
envVariables = require('../envVariables');

// Polyfill for jose in Node.js (CommonJS)
if (!globalThis.crypto) {
  const { webcrypto } = require('crypto');
  globalThis.crypto = webcrypto;
}

class JwtAuthGuard {
  constructor() {}

  async canActivate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ message: 'Authorization header missing' });
    }

    const token = authHeader.split(' ')[1];

    try {
      const { jwtDecrypt, jwtVerify } = await import('jose');

      // Decryption key (for JWE)
      const secretKey = process.env.JOSE_SECRET;
      const decryptionKey = new Uint8Array(
        createHash('sha256').update(secretKey).digest()
      );

      // Decrypt the outer JWT (JWE)
      const { payload: decryptedPayload } = await jwtDecrypt(token, decryptionKey);

      if (!decryptedPayload.jwtSignedToken) {
        return res.status(401).json({ message: 'jwtSignedToken not found in decrypted payload' });
      }

      // Verify the inner signed JWT (JWS)
      const jwtSignedToken = String(decryptedPayload.jwtSignedToken);
      const jwtSigninKey = new TextEncoder().encode(
        process.env.JWT_SIGNIN_PRIVATE_KEY
      );

      const { payload: verifiedPayload } = await jwtVerify(jwtSignedToken, jwtSigninKey);

      req.user = verifiedPayload;
      next();
    } catch (err) {
      console.error('JWT error:', err);
      return res.status(401).json({ message: 'Invalid or expired token' });
    }
  }
}

module.exports = new JwtAuthGuard();