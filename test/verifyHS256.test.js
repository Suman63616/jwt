const jwt = require('../index');
const expect = require('chai').expect;


describe('JWT verify with HS256 algorithm', function () {
  const secret = 'test';
  const expiresIn='15m';
  const token = jwt.sign({ sub: '1234567890' }, secret, {expiresIn,algorithm :'HS256'});
  
  it('should return the decoded payload on successful verification of HS256', function (done) {
    jwt.verify(token, secret, function (err, decoded) {
      expect(err).to.equal(null);
      expect(decoded.sub).to.equal('1234567890');
      done();
    });
  });

  it('should return an error for an invalid token', function (done) {
    jwt.verify(token + 'invalid', secret,  function (err, decoded) {
      expect(err).to.not.equal(null);
      done();
    });
  });

  it('should throw an error for an invalid signature', (done) => {
    
    const payload = { id: 123 };
   
    jwt.verify(token.replace(/\./g, 'x'), secret,  (err, decoded) => {
      expect(err).to.be.an('error');
      expect(decoded).to.equal(false);
      done();
    });
  });

  it('should return an error for an invalid secret', function (done) {
    jwt.verify(token, secret + 'invalid',  function (err, decoded) {
      expect(err).to.not.equal(null);
      done();
    });
  });

  it('should return an error for an invalid algorithm', function (done) {
    const token = jwt.sign({ sub: '1234567890' }, secret, {algorithm :'HS356'});
    jwt.verify(token, secret, function (err, decoded) {
      expect(err).to.not.equal(null);
      done();
    });
  });

  it('should throw an error for an expired token', function (done) {
    const payload = { sub: '1234567890', name: 'John Doe' };
   
    const token = jwt.sign(payload, secret, { expiresIn: 1,algorithm :'HS256' });
    setTimeout(function () {
      jwt.verify(token, secret, function (err, decoded) {
        try {
          expect(err).to.be.an.instanceOf(Error);
          done();
        } catch (e) {
          done(e);
        }
      });
    }, 1900);
  });
});
