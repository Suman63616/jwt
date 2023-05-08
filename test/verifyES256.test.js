const fs= require('fs')
const jwt = require('../index');
const expect = require('chai').expect;
const privateKey = fs.readFileSync('esPrivate.key');
const publicKey = fs.readFileSync('esPublic.key');
const invalidPublic = fs.readFileSync('invalidPublic.key');
const secret = privateKey;



describe('JWT verify with ES256 algorithm', () => {
    it('should return the decoded payload on successful verification of RS256', () => {
      const payload = { sub: '1234567890', name: 'John Doe', iat: 1516239022 };
      const token = jwt.sign(payload, secret, {algorithm:'ES256'});
      jwt.verify(token, publicKey, (err, decoded) => {
        expect(err).to.be.null;
        expect(decoded.sub).to.equal('1234567890');
        
      });
    });

    it('should throw an error when the token is invalid', () => {
      const token = 'invalid.token';
      jwt.verify(token, secret,  (err, decoded) => {
        expect(err).to.be.an('error');
        expect(decoded).to.be.false;
      });
    });

    it('should throw an error for an invalid signature', (done) => {
    
      const payload = { id: 123 };
      const token = jwt.sign(payload, secret, 'RS356');
      jwt.verify(token.replace(/\./g, 'x'), publicKey,  (err, decoded) => {
        expect(err).to.be.an('error');
        expect(decoded).to.equal(false);
        done();
      });
    });

    it('should return an error for an invalid secret', function (done) {
      const payload = { id: 123 };
      const token = jwt.sign(payload, secret, {algorithm:'ES256'});
      jwt.verify(token, invalidPublic.key,  function (err, decoded) {
        expect(err).to.not.equal(null);
        done();
      });
    });

    it('should return an error for an invalid algorithm', function (done) {
      const payload = { id: 123 };
      const token = jwt.sign(payload, secret, {algorithm:'RS356'});
      jwt.verify(token, secret, function (err, decoded) {
        expect(err).to.not.equal(null);
        
        done();
      });
    });

    it('should throw an error if the token has expired //testing with negative value', () => {
      const expiresIn = -3600;
      const payload = { sub: '1234567890', name: 'John Doe', iat: 1516239022 };
      const token = jwt.sign(payload, secret,  { expiresIn,algorithm:'ES256' });
      jwt.verify(token, secret,  (err, decoded) => {
        expect(err).to.not.be.null;
        expect(decoded).to.be.false;
        
      });
    });

    it('should throw an error if the token has expired //testing with positive value', async function()  {
     
      const expiresIn = 1;
      const payload = { sub: '1234567890', name: 'John Doe', iat: 1516239022 };
      const token = jwt.sign(payload, secret, { expiresIn,algorithm:'ES256' });
  
      // Wait for 2 seconds before verifying the token
      await new Promise(resolve => setTimeout(resolve, 2000));
      this.timeout(5000);
      jwt.verify(token, secret,  (err, decoded) => {
        if(err){
        expect(err).to.not.be.null;
        expect(err.message).to.be.equal('Token has expired');
        
        }
        else
        {
          expect(err).to.be.null;
        }
      });
  });

  it('should not throw error for token not expired', async function()  {
     
    const expiresIn = 3;
    const payload = { sub: '1234567890', name: 'John Doe', iat: 1516239022 };
    const token = jwt.sign(payload, secret, { expiresIn,algorithm:'ES256' });

    // Wait for 2 seconds before verifying the token
    await new Promise(resolve => setTimeout(resolve, 2000));
    this.timeout(5000);
    jwt.verify(token, secret,  (err, decoded) => {
      
        expect(err).to.be.null;
        expect(decoded.sub).to.equal('1234567890');
      
    });
});
  });
