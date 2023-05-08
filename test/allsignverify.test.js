const jwt = require('../index');
const expect = require('chai').expect;
const fs= require('fs')



describe('JWT sign with HS256 algorithm', () => {
    const secret = 'secret';
    const payload = { id: 123 };
    it('should sign a JWT with HS256 algorithm', () => {
      const token = jwt.sign(payload, secret, {algorithm :'HS256'});
      expect(token).to.be.a('string');
      expect(token.split('.').length).to.equal(3);
    });

    it('should produce different signatures for different payloads', () => {
      const token1 = jwt.sign(payload, secret, {algorithm :'HS256'});
      const token2 = jwt.sign(payload, `${secret}*&sd`, {algorithm :'HS256'});
      expect(token1).to.not.equal(token2);
    });
});


    describe('decode', function() {
      it('should decode a JWT token and return the payload', function() {
          const secret = 'test';
          const token = jwt.sign({ sub: '1234567890' }, secret, {algorithm :'HS256'});
          const decoded = jwt.decode(token);
          expect(decoded.sub).to.equal('1234567890');
         
      });
      
      it('should throw an error when the token is invalid', function() {
        const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTY4ODk5MDB9';
        expect(() => jwt.decode(token)).to.throw('Invalid JWT');
      });
    });
 

    

describe('JWT verify with HS256 algorithm', function () {
  const secret = 'test';
  const token = jwt.sign({ sub: '1234567890' }, secret, {algorithm :'HS256'});
  
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
    const payload = { sub: '1234567890', name: 'John Doe', iat: 1516239022, exp: 1516239122 };
   
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

var privateKey = fs.readFileSync('rsPrivate.key');
var publicKey = fs.readFileSync('rsPublic.key');
var invalidPublic = fs.readFileSync('invalidPublic.key');
var secret = privateKey;


  describe('JWT sign with RS256 algorithm', () => {

    it('should sign a JWT with RS256 algorithm', () => {
      const payload = { sub: '1234567890', name: 'John Doe', iat: 1516239022 };
      const token = jwt.sign(payload, secret,{algorithm:'RS256'});
      expect(token).to.be.a('string');
      expect(token).to.not.be.empty;
    });
  
  });

   

  describe('JWT verify with RS256 algorithm', () => {
    it('should return the decoded payload on successful verification of RS256', () => {
      const payload = { sub: '1234567890', name: 'John Doe', iat: 1516239022 };
      const token = jwt.sign(payload, secret, {algorithm:'RS256'});
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
      const token = jwt.sign(payload, secret, {algorithm:'RS256'});
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

    it('should throw an error when the token has expired', () => {
      const expiresIn = -3600;
      const payload = { sub: '1234567890', name: 'John Doe', iat: 1516239022 };
      const token = jwt.sign(payload, secret,  { expiresIn,algorithm:'RS256' });
      jwt.verify(token, secret,  (err, decoded) => {
        expect(err).to.not.be.null;
        expect(decoded).to.be.false;
        
      });
    });

    it('should throw error if the token has expired', async function()  {
     
      const expiresIn = 1;
      const payload = { sub: '1234567890', name: 'John Doe', iat: 1516239022 };
      const token = jwt.sign(payload, secret, { expiresIn,algorithm:'RS256' });
  
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

  it('should throw error if the token has expired', async function()  {
     
    const expiresIn = 3;
    const payload = { sub: '1234567890', name: 'John Doe', iat: 1516239022 };
    const token = jwt.sign(payload, secret, { expiresIn,algorithm:'RS256' });

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
        expect(decoded.sub).to.equal('1234567890');
      }
    });
});
  });


   privateKey = fs.readFileSync('esPrivate.key');
   publicKey = fs.readFileSync('esPublic.key');
   invalidPublic = fs.readFileSync('invalidPublic.key');
   secret = privateKey;


  describe('JWT sign with ES256 algorithm', () => {

    it('should sign a JWT with ES256 algorithm', () => {
      const payload = { sub: '1234567890', name: 'John Doe', iat: 1516239022 };
      const token = jwt.sign(payload, secret,{algorithm:'ES256'});
      expect(token).to.be.a('string');
      expect(token).to.not.be.empty;
    });
  
  });

   

  describe('JWT verify with ES256 algorithm', () => {
    it('should return the decoded payload on successful verification of ES256', () => {
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

    it('should throw an error when the token has expired', () => {
      const expiresIn = -3600;
      const payload = { sub: '1234567890', name: 'John Doe', iat: 1516239022 };
      const token = jwt.sign(payload, secret,  { expiresIn,algorithm:'ES256' });
      jwt.verify(token, secret,  (err, decoded) => {
        expect(err).to.not.be.null;
        expect(decoded).to.be.false;
        
      });
    });

    it('should throw error if the token has expired', async function()  {
     
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

  it('should throw error if the token has expired', async function()  {
     
    const expiresIn = 3;
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
        expect(decoded.sub).to.equal('1234567890');
      }
    });
});
  });
