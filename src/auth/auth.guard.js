const { createHash, webcrypto } = require('node:crypto');
const http = require('node:http');
const https = require('node:https');
require('dotenv').config();

// Polyfill for jose in Node.js (CommonJS)
if (!globalThis.crypto) {
  globalThis.crypto = webcrypto;
}

const postJson = (urlStr, body) => {
  return new Promise((resolve, reject) => {
    try {
      const url = new URL(urlStr);
      const data = JSON.stringify(body);
      const transport = url.protocol === 'https:' ? https : http;
      const req = transport.request(
        url,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(data),
          },
        },
        (res) => {
          let responseBody = '';
          res.on('data', (chunk) => {
            responseBody += chunk;
          });
          res.on('end', () => {
            try {
              const parsed = JSON.parse(responseBody);
              resolve(parsed);
            } catch (parseErr) {
              reject(parseErr);
            }
          });
        }
      );
      req.on('error', (err) => {
        reject(err);
      });
      req.write(data);
      req.end();
    } catch (err) {
      reject(err);
    }
  });
};

const getEncryptionKey = (jose) => {
  const encKeyStr = process.env.JWT_ENCRYPTION_PRIVATE_KEY;
  if (encKeyStr && jose?.base64url) {
    try {
      return jose.base64url.decode(encKeyStr.replace(/^["']|["']$/g, '').trim());
    } catch (e) {
      console.warn('Failed to base64url decode JWT_ENCRYPTION_PRIVATE_KEY, falling back to secret hash', e);
    }
  }
  const secretKey = (process.env.JOSE_SECRET || '').replace(/^["']|["']$/g, '').trim();
  return createHash('sha256').update(secretKey).digest();
};

const getSigningKey = () => {
  const signinKeyStr = (process.env.JWT_SIGNIN_PRIVATE_KEY || '').replace(/^["']|["']$/g, '').trim();
  return new TextEncoder().encode(signinKeyStr);
};

class JwtAuthGuard {
  constructor() {}

  async checkTokenStatus(userId, token) {
    const orcServiceUrl = process.env.ALL_ORC_SERVICE_URL;
    const loginServiceUrl = process.env.AXL_LOGIN_SERVICE_URL;

    if (orcServiceUrl) {
      try {
        const response = await this.postJson(orcServiceUrl, {
          user_id: userId,
          token: token,
        });
        const isActive =
          response?.result?.isActive ??
          response?.data?.result?.isActive ??
          response?.isActive ??
          null;
        if (isActive !== null) {
          return { isActive: Boolean(isActive) };
        }
      } catch (err) {
        console.error('Error fetching token status from orchestration service:', err?.message || err);
      }
    }

    if (loginServiceUrl) {
      try {
        const statusData = await this.postJson(
          `${loginServiceUrl}/api/v1/virtualId/tokenStatus`,
          {
            user_id: Number(userId) || userId,
          }
        );
        const activeToken =
          statusData?.responseObj?.responseDataParams?.data?.token ??
          statusData?.data?.token ??
          statusData?.token ??
          null;
        if (activeToken) {
          return { isActive: activeToken === token };
        }
      } catch (fetchErr) {
        console.error('Error fetching token status from axl-login-service:', fetchErr?.message || fetchErr);
      }
    }

    return { isActive: false };
  }

  async canActivate(req, res, next) {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (!authHeader) {
      return res.status(401).json({ message: 'Authorization header missing' });
    }

    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer' || !parts[1]) {
      return res.status(401).json({ message: 'Invalid authorization header format' });
    }
    const token = parts[1];

    try {
      const jose = await import('jose');

      const encryptionKey = getEncryptionKey(jose);
      const { payload: decryptedPayload } = await jose.jwtDecrypt(token, encryptionKey);

      if (!decryptedPayload.jwtSignedToken) {
        return res.status(401).json({ message: 'jwtSignedToken not found in decrypted payload' });
      }

      const jwtSignedToken = String(decryptedPayload.jwtSignedToken);
      const jwtSigninKey = getSigningKey();

      const { payload: verifiedPayload } = await jose.jwtVerify(jwtSignedToken, jwtSigninKey);

      const { exp } = verifiedPayload;
      const virtualId =
        verifiedPayload.virtual_id ??
        verifiedPayload.virtualId ??
        verifiedPayload.userId;

      if (!exp || exp <= Math.floor(Date.now() / 1000)) {
        return res.status(401).json({ message: 'Token expired' });
      }

      if (!virtualId) {
        return res.status(401).json({ message: 'Missing virtual_id in token payload' });
      }

      const { isActive } = await this.checkTokenStatus(virtualId, token);
      if (!isActive) {
        return res.status(401).json({ message: 'User is logged out' });
      }

      req.user = verifiedPayload;
      next();
    } catch (err) {
      if (err && (err.code === 'ERR_JWT_EXPIRED' || (typeof err.message === 'string' && err.message.includes('expired')))) {
        return res.status(401).json({ message: 'Token expired' });
      }
      console.error('JWT error:', err.message || err);
      return res.status(401).json({ message: 'Invalid or expired token' });
    }
  }
}

const instance = new JwtAuthGuard();
instance.getEncryptionKey = getEncryptionKey;
instance.getSigningKey = getSigningKey;
instance.postJson = postJson;

module.exports = instance;
