const assert = require('assert');

const JWT = require('../../lib/jwt');

module.exports = function( algorithm, data )
{
    let jwt;
    
    it( 'should instantiate ' + algorithm + ' JWT token', () =>
    {
        jwt = new JWT({ [algorithm]: data });
    });
    
    it( 'should create ' + algorithm + ' JWT token', () =>
    {
        let payload = { id: 123456 };
        let token = jwt.create( payload );

        assert.ok( typeof token === 'string' && (/[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/).test( token ), 'Invalid JWT token' );

        let parsed_token = jwt.parse( token );

        assert.ok( parsed_token.ok, 'Could not parse JWT token' );
        assert.ok( parsed_token.header.typ === 'JWT', 'Invalid JWT token type' );
        assert.ok( parsed_token.header.alg === algorithm, 'Invalid JWT token algorithm' );
        assert.ok( parsed_token.remaining === Infinity, 'Invalid JWT token validity' );
    });

    it( 'should not validate empty JWT token', () =>
    {
        for( let empty of [ undefined, null, 0, '', {}, 'eyJ0eXAiOiJKV1QifQ.eyJpZCI6MTIzNDU2LCJpYXQiOjE1NzIwODI0NzZ9.mejQJ73v49SJa9ZYkstjUCYmeDxMbyiD7FeOcZn1kFhm_GYCU4jtBEg4Eh-le3Xe-BG8mOTToMSB4en_HqFP2A' ])
        {
            let parsed_token = jwt.parse( empty );
            
            assert.ok( !parsed_token.ok, 'Validated empty JWT token' );
            assert.ok( parsed_token.error === 'invalid', 'Mismatching JWT token error' );
        }
    });
    
    it( 'should not validate JWT token with invalid signature', () =>
    {
        let payload = { id: 123456 };
        let token = jwt.create( payload );
        let parsed_token = jwt.parse( token );

        assert.ok( typeof token === 'string' && (/[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/).test( token ), 'Invalid JWT token' );
        assert.ok( parsed_token.ok, 'Could not parse JWT token' );

        parsed_token = jwt.parse( token.replace(/\.([^.]+)$/,( _, sgn ) => '.' + sgn.split('').reverse().join('')));

        assert.ok( !parsed_token.ok, 'Validated invalid token' );
        assert.ok( parsed_token.error === 'unauthorized', 'Bad error on token' );
    });
    
    it( 'should follow expires claim on JWT token', () =>
    {
        assert.ok( jwt.parse( jwt.create({ id: 123456 }, algorithm, { expires: undefined })).ok, 'Token not ok' );
        assert.ok( jwt.parse( jwt.create({ id: 123456 }, algorithm, { expires: null })).ok, 'Token not ok' );
        assert.ok( jwt.parse( jwt.create({ id: 123456 }, algorithm, { expires: '' })).ok, 'Token not ok' );
        assert.ok( jwt.parse( jwt.create({ id: 123456 }, algorithm, { expires: 0 })).ok, 'Token not ok' );

        for( let expires of [ 100, 946079999, Date.now() + 10000, new Date( Date.now() + 10000 ), '10s', '10m', '10h', '10d', '10w', '10y' ])
        {
            let token = jwt.create({ id: 123456 }, algorithm, { expires });
            let parsed_token = jwt.parse( token );

            assert.ok( parsed_token.ok, 'Token not ok' );
            assert.ok( parsed_token.payload.exp > Date.now() / 1000, 'Token not ok' );
            assert.ok( parsed_token.remaining < Infinity && parsed_token.remaining > 0, 'Invalid JWT token validity' );
        }
        
        for( let expires of [ -100, 946080001, Date.now() - 10000, '-10s', '-10m', '-10h', '-10d', '-10w', '-10y' ])
        {
            let token = jwt.create({ id: 123456 }, { expires });
            let parsed_token = jwt.parse( token );

            assert.ok( !parsed_token.ok, 'Token ok' );
            assert.ok( parsed_token.error === 'expired', 'Token ok' );
            assert.ok( parsed_token.claims.exp < Date.now() / 1000, 'Token ok' );
            assert.ok( parsed_token.remaining === 0, 'Invalid JWT token validity' );
        }
    });

    it( 'should follow notBefore claim on JWT token', () =>
    {
        for( let starts of [ 100, 946079999, Date.now() + 10000, new Date( Date.now() + 10000 ), '10s', '10m', '10h', '10d', '10w', '10y' ])
        {
            let token = jwt.create({ id: 123456 }, algorithm, { starts });
            let parsed_token = jwt.parse( token );

            assert.ok( !parsed_token.ok, 'Token not ok' );
            assert.ok( parsed_token.error === 'inactive', 'Token ok' );
            assert.ok( parsed_token.payload.nbf > Date.now() / 1000, 'Token not ok' );
        }
        
        for( let starts of [ -100, 946080001, Date.now() - 10000, '-10s', '-10m', '-10h', '-10d', '-10w', '-10y' ])
        {
            let token = jwt.create({ id: 123456 }, { starts });
            let parsed_token = jwt.parse( token );

            assert.ok( parsed_token.ok, 'Token ok' );
            assert.ok( parsed_token.claims.nbf < Date.now() / 1000, 'Token ok' );
        }
    });
}