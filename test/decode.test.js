
const jwt = require('../index');
const { expect } = require('chai');

describe('decode', () => {
it('should decode the token payload', () => {
const token = jwt.sign({ name: 'TomDoesTech' },'shhhh');
const decoded = jwt.decode( token );
expect(decoded.name).to.equal('TomDoesTech');
});
});