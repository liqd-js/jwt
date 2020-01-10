'use strict';
const fs = require('fs');

const ALGORITHMS = 
{
    HS512: 'P455PHR45E',
    HS384: 'P455PHR45E',
    HS256: 'P455PHR45E',
    RS512:
    {
        key: fs.readFileSync( __dirname + '/keys/rsa.2048.key' ),
        pub: fs.readFileSync( __dirname + '/keys/rsa.2048.pub' )
    },
    RS384:
    {
        key: fs.readFileSync( __dirname + '/keys/rsa.2048.key' ),
        //pub: fs.readFileSync( __dirname + '/keys/rsa.2048.pub' )
    },
    RS256:
    {
        key: fs.readFileSync( __dirname + '/keys/rsa.2048.key' ),
        pub: fs.readFileSync( __dirname + '/keys/rsa.2048.pub' )
    },
    ES512:
    {
        key: fs.readFileSync( __dirname + '/keys/ec.521.key' ),
        pub: fs.readFileSync( __dirname + '/keys/ec.521.pub' )
    },
    ES384:
    {
        key: fs.readFileSync( __dirname + '/keys/ec.384.key' ),
        //pub: fs.readFileSync( __dirname + '/keys/ec.384.pub' )
    },
    ES256:
    {
        key: fs.readFileSync( __dirname + '/keys/ec.256.key' ),
        pub: fs.readFileSync( __dirname + '/keys/ec.256.pub' )
    }
}

describe( 'Tests', ( done ) =>
{
    var files = fs.readdirSync( __dirname + '/tests' );
    
    for( let algorithm in ALGORITHMS )
    {
        //if( algorithm !== 'ES512' ) continue;

        describe( algorithm, () =>
        {
            for( let file of files )
            {
                if( !file.match(/\.js$/) ){ continue; }

                describe( file, () =>
                {
                    require( __dirname + '/tests/' + file )( algorithm, ALGORITHMS[algorithm] );
                });
            }
        });
    }
});
