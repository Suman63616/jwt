const jwt = require('../index');
const expect = require('chai').expect;

describe('JWT expiry verification', () => {
  const secret ='secret'
  it('should throw an error if the token has expired //testing with negative value', () => {
    const expiresIn = -3600;
    const payload = { sub: '1234567890', name: 'John Doe', iat: 1516239022 };
    const token = jwt.sign(payload, secret,  { expiresIn,algorithm:'HS256' });
    jwt.verify(token, secret,  (err, decoded) => {
      expect(err).to.not.be.null;
      expect(decoded).to.be.false;
      
    });
  });

  it('should throw an error for invalid exp', () => {
    const expiresIn = '$wdsfd';
    const payload = { sub: '1234567890', name: 'John Doe', iat: 1516239022 };
    const token = jwt.sign(payload, secret,  { expiresIn,algorithm:'HS256' });
   
    jwt.verify(token, secret,  (err, decoded) => {
      expect(err).to.not.be.null;
      expect(err.message).to.be.equal('invalid exp value');
      expect(decoded).to.be.false;
      
    });
  });

  it('should throw an error if the token has expired //testing with positive value', async function()  {
   
    const expiresIn = '1s';
    const payload = { sub: '1234567890', name: 'John Doe', iat: 1516239022 };
    const token = jwt.sign(payload, secret, { expiresIn,algorithm:'HS256' });

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

it('should not throw error and decode the token for token not expired', async function()  {
   
  const expiresIn = '3s';
  const payload = { sub: '1234567890', name: 'John Doe', iat: 1516239022 };
  const token = jwt.sign(payload, secret, { expiresIn,algorithm:'HS256' });

  // Wait for 2 seconds before verifying the token
  await new Promise(resolve => setTimeout(resolve, 2000));
  this.timeout(5000);
  jwt.verify(token, secret,  (err, decoded) => {
    
      expect(err).to.be.null;
      expect(decoded.sub).to.equal('1234567890');
    
  });
});

});