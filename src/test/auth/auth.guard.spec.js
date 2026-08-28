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
    it('should decode base64url if JWT_ENCRYPTION_PRIVATE_KEY is set', () => {
      process.env.JWT_ENCRYPTION_PRIVATE_KEY = 'base64key';
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
      process.env.JWT_ENCRYPTION_PRIVATE_KEY = 'invalid-base64';
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
    it('should encode JWT_SIGNIN_PRIVATE_KEY into Uint8Array', () => {
      process.env.JWT_SIGNIN_PRIVATE_KEY = 'secret-signin-key';
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

  describe('checkTokenStatus', () => {
    it('should return isActive false if no URLs are configured', async () => {
      delete process.env.ALL_ORC_SERVICE_URL;
      delete process.env.AXL_LOGIN_SERVICE_URL;

      const result = await authGuard.checkTokenStatus('12345', 'mock-token');
      expect(result).to.deep.equal({ isActive: false });
    });

    it('should return isActive true when orchestration service returns isActive: true', async () => {
      process.env.ALL_ORC_SERVICE_URL = 'http://localhost:3009/api/virtualId/tokenStatus';
      delete process.env.AXL_LOGIN_SERVICE_URL;

      sinon.stub(authGuard, 'postJson').resolves({ result: { isActive: true } });

      const result = await authGuard.checkTokenStatus('12345', 'mock-token');
      expect(result).to.deep.equal({ isActive: true });
    });

    it('should return isActive true when login service returns matching token', async () => {
      delete process.env.ALL_ORC_SERVICE_URL;
      process.env.AXL_LOGIN_SERVICE_URL = 'http://localhost:8000';

      sinon.stub(authGuard, 'postJson').resolves({
        responseObj: {
          responseDataParams: {
            data: {
              token: 'target-token',
            },
          },
        },
      });

      const result = await authGuard.checkTokenStatus('12345', 'target-token');
      expect(result).to.deep.equal({ isActive: true });
    });

    it('should return isActive false when login service returns mismatched token', async () => {
      delete process.env.ALL_ORC_SERVICE_URL;
      process.env.AXL_LOGIN_SERVICE_URL = 'http://localhost:8000';

      sinon.stub(authGuard, 'postJson').resolves({
        data: {
          token: 'different-token',
        },
      });

      const result = await authGuard.checkTokenStatus('12345', 'target-token');
      expect(result).to.deep.equal({ isActive: false });
    });

    it('should fallback to login service if orchestration service rejects', async () => {
      process.env.ALL_ORC_SERVICE_URL = 'http://localhost:3009/api/virtualId/tokenStatus';
      process.env.AXL_LOGIN_SERVICE_URL = 'http://localhost:8000';

      const postJsonStub = sinon.stub(authGuard, 'postJson');
      postJsonStub.onFirstCall().rejects(new Error('Network error'));
      postJsonStub.onSecondCall().resolves({
        token: 'target-token',
      });

      const result = await authGuard.checkTokenStatus('12345', 'target-token');
      expect(result).to.deep.equal({ isActive: true });
    });
  });
});
