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
      const secretKey = process.env.JOSE_SECRET; // replace with actual secret from env ideally
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
















// const { createHash,createSecretKey } = require('crypto');
// // const { jwtDecrypt, jwtVerify } = require('jose')

// class JwtAuthGuard {
//   constructor() {}

//   async canActivate(req, res, next) {
//     const authHeader = req.headers.authorization;
//     console.log(authHeader,'header')

//     if (!authHeader) {
//       return res.status(401).json({ message: 'Authorization header missing' });
//     }

//     const token = authHeader.split(' ')[1];

//     try {
//       // Dynamically import `jose` since it's an ESM-only module
//       const { jwtDecrypt, jwtVerify } = await import('jose');
//       console.log('first')

//       const secretKey = "m9KqXr3YwPqQZfU7VcG5X9F2YZ8NqJp7X3YzB6MkU3E=" || '';
//       const hash = createHash('sha256').update(secretKey).digest();
//       const decryptionKey = createSecretKey(hash);


//       const jwtDecryptedToken = await jwtDecrypt(token, decryptionKey);
      
//       if (!jwtDecryptedToken.payload.jwtSignedToken) {
//         return res.status(401).json({ message: 'jwtSignedToken not found in decrypted payload' });
//       }

//       const jwtSignedToken = String(jwtDecryptedToken.payload.jwtSignedToken);
//       const jwtSigninKey = new TextEncoder().encode("aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789+/ABCDEF=");
//       const verifiedToken = await jwtVerify(jwtSignedToken, jwtSigninKey);

//       req.user = verifiedToken.payload;
//       next();
//     } catch (err) {
//       return res.status(401).json({ message: 'Invalid or expired token' });
//     }
//   }
// }

// module.exports = new JwtAuthGuard();

















// const { Injectable, CanActivate, UnauthorizedException } = require('@nestjs/common');
// const { JwtService } = require('@nestjs/jwt');
// const { createHash } = require('crypto');
// const jose = require('jose');


// class JwtAuthGuard {
//   constructor(jwtService) {
//     this.jwtService = jwtService;
//   }

//   async canActivate(context) {
//     const request = context.switchToHttp().getRequest();
//     const authHeader = request.headers.authorization;

//     if (!authHeader) {
//       throw new UnauthorizedException('Authorization header missing');
//     }

//     const token = authHeader.split(' ')[1];

//     try {
//       // Step 1: Correctly Generate Encryption Key
//       const secretKey = process.env.JOSE_SECRET || '';
//       const hash = createHash('sha256').update(secretKey).digest();

//       // Step 2: Decrypt the Token
//       const jwtDecryptedToken = await jose.jwtDecrypt(token, hash);

//       if (!jwtDecryptedToken.payload.jwtSignedToken) {
//         throw new Error("jwtSignedToken not found in decrypted payload");
//       }

//       // Step 3: Verify the Signed JWT
//       const jwtSignedToken = String(jwtDecryptedToken.payload.jwtSignedToken);
//       const jwtSigninKey = new TextEncoder().encode(process.env.JWT_SIGNIN_PRIVATE_KEY);
//       const verifiedToken = await jose.jwtVerify(jwtSignedToken, jwtSigninKey);

//       // Step 4: Attach User Data to Request
//       request.user = verifiedToken.payload;

//       return true;
//     } catch (err) {
//       throw new UnauthorizedException('Invalid or expired token');
//     }
//   }
// }

// module.exports = { JwtAuthGuard };
