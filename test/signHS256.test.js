const jwt = require('../index');
const expect = require('chai').expect;

require('dotenv').config()



describe('JWT sign with HS256 algorithm', () => {
  const secret = `${process.env.ACCESS_TOKEN_SECRET}`
    const payload = { id: 123 };
  it('should sign a JWT with HS256 algorithm', () => {
    const token = jwt.sign(payload, secret);
    expect(token).to.be.a('string');
    expect(token.split('.').length).to.equal(3);
  });


  it('should add the expiry to the payload', () => {
    
    const token = jwt.sign(payload, secret,{expiresIn:30}).split('.')[1];

    expect(JSON.parse(Buffer.from(token, 'base64').toString()).exp).to.be.a('number');
  });

  it('should add the algorithm to the payload', () => {
    
    const token = jwt.sign(payload, secret,{expiresIn:30,algorithm:'HS256'}).split('.')[1];

    expect(JSON.parse(Buffer.from(token, 'base64').toString()).exp).to.be.a('number');
    expect(JSON.parse(Buffer.from(token, 'base64').toString()).alg).to.be.a('string');

  });


  it('should produce different signatures for different payloads', () => {
    const token1 = jwt.sign(payload, secret, {algorithm :'HS256'});
    const token2 = jwt.sign(payload, `${secret}*&sd`, {algorithm :'HS256'});
    expect(token1).to.not.equal(token2);
  });
});
