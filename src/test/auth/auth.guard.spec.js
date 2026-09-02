const chai = require('chai');
const expect = chai.expect;
const sinon = require('sinon');
const authGuard = require('../../auth/auth.guard');

describe('auth.guard in all-telemetry-mw', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = Object.assign({}, originalEnv);
  });

  afterEach(() => {
    process.env = originalEnv;
    sinon.restore();
  });

  describe('getEncryptionKey', () => {
    it('should decode base64url if JOSE_ENCRYPTION_PRIVATE_KEY is set', () => {
      process.env.JOSE_ENCRYPTION_PRIVATE_KEY = 'base64key';
      const mockDecoded = new Uint8Array([1, 2, 3]);
      const mockJose = {
        base64url: {
          decode: sinon.stub().returns(mockDecoded),
        },
      };

      const result = authGuard.getEncryptionKey(mockJose);
      expect(mockJose.base64url.decode.calledWith('base64key')).to.be.true;
      expect(result).to.equal(mockDecoded);
    });

    it('should fallback to sha256 hash if base64url decode throws error', () => {
      process.env.JOSE_ENCRYPTION_PRIVATE_KEY = 'invalid-base64';
      process.env.JOSE_SECRET = 'my-secret';
      const mockJose = {
        base64url: {
          decode: sinon.stub().throws(new Error('Invalid base64url')),
        },
      };

      const result = authGuard.getEncryptionKey(mockJose);
      expect(result).to.be.instanceOf(Buffer);
      expect(result.length).to.equal(32);
    });
  });

  describe('getSigningKey', () => {
    it('should encode JOSE_SIGNIN_PRIVATE_KEY into Uint8Array', () => {
      process.env.JOSE_SIGNIN_PRIVATE_KEY = 'secret-signin-key';
      const result = authGuard.getSigningKey();
      expect(result).to.deep.equal(new TextEncoder().encode('secret-signin-key'));
    });
  });

  describe('canActivate', () => {
    it('should return 401 when Authorization header is missing', async () => {
      const req = { headers: {} };
      const res = {
        status: sinon.stub().returnsThis(),
        json: sinon.stub(),
      };
      const next = sinon.spy();

      await authGuard.canActivate(req, res, next);
      expect(res.status.calledWith(401)).to.be.true;
      expect(res.json.calledWith({ message: 'Authorization header missing' })).to.be.true;
      expect(next.called).to.be.false;
    });

    it('should return 401 when Authorization header format is invalid', async () => {
      const req = { headers: { authorization: 'Basic some-token' } };
      const res = {
        status: sinon.stub().returnsThis(),
        json: sinon.stub(),
      };
      const next = sinon.spy();

      await authGuard.canActivate(req, res, next);
      expect(res.status.calledWith(401)).to.be.true;
      expect(res.json.calledWith({ message: 'Invalid authorization header format' })).to.be.true;
      expect(next.called).to.be.false;
    });

    it('should return 401 when token status check returns isActive false', async () => {
      const req = { headers: { authorization: 'Bearer valid.jwt.token' } };
      const res = {
        status: sinon.stub().returnsThis(),
        json: sinon.stub(),
      };
      const next = sinon.spy();

      sinon.stub(authGuard, 'checkTokenStatus').resolves({ isActive: false });

      await authGuard.canActivate(req, res, next);
      expect(res.status.calledWith(401)).to.be.true;
      expect(next.called).to.be.false;
    });
  });
});
