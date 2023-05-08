const fs= require('fs')
const jwt = require('../index');
const expect = require('chai').expect;
const privateKey = fs.readFileSync('private.key');
const private2Key = fs.readFileSync('private2.key');
var secret = privateKey;

describe('JWT sign with RS256 algorithm', () => {
    const payload = { sub: '1234567890', name: 'John Doe' };
    it('should sign a JWT with RS256 algorithm', () => {
      
      const token = jwt.sign(payload, secret,{algorithm:'RS256'});
      expect(token).to.be.a('string');
      expect(token).to.not.be.empty;
    });

    
    
      it('should add expiry and  algorithm to the payload', () => {
        
        const token = jwt.sign(payload, secret,{expiresIn:30,algorithm:'RS256'}).split('.')[1];
    
        expect(JSON.parse(Buffer.from(token, 'base64').toString()).exp).to.be.a('number');
        expect(JSON.parse(Buffer.from(token, 'base64').toString()).alg).to.be.a('string');
    
      });
    
    
      it('should produce different signatures for different payloads', () => {

        const token1 = jwt.sign(payload, secret, {algorithm :'RS256'});
        secret = private2Key;
        const token2 = jwt.sign(payload, secret, {algorithm :'RS256'});
        expect(token1).to.not.equal(token2);
      });
  
  });