'use strict';

const crypto = require('crypto');

const ALGORITHMS = [ 'ES512', 'ES384', 'ES256', 'RS512', 'RS384', 'RS256', 'HS512', 'HS384', 'HS256' /*, 'PS256', 'PS384' */ ];
const INTERVALS = { ms: 1 / 1000, s : 1, m: 60, h: 60 * 60, d: 24 * 60 * 60, w: 7 * 24 * 60 * 60, y: 365 * 24 * 60 * 60 };

const toBase64URL = ( base64 ) => base64.replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
const fromBase64URL = ( base64url ) => base64url.replace(/\-/g,'+').replace(/_/g,'/');
const base64URLencode = ( data ) => toBase64URL( Buffer.from( data, 'utf8' ).toString('base64') );
const base64URLdecode = ( data ) => Buffer.from( fromBase64URL( data ), 'base64' ).toString('utf8');
const encode = ( data ) => base64URLencode( JSON.stringify( data ));
const decode = ( data ) => JSON.parse( base64URLdecode( data ));
const timestamp = ( value ) =>
{
    if( value instanceof Date )
    {
        return Math.floor( value.getTime() / 1000 );
    }
    else if( typeof value === 'number' )
    {
        if( value > 946080000000 ){ value = Math.floor( value / 1000 )}
        else if( value < 946080000 ){ value += Math.floor( Date.now() / 1000 )}
        else{ value = Math.floor( value )}
    }
    else// if( typeof value === 'string' )
    {
        value = Math.floor( Date.now() / 1000 + parseFloat( value ) * INTERVALS[value.trim().toLowerCase().split(/\s*([a-zA-Z])/)[1]]);
    }

    return value;
}

class JSONWebToken
{
    #error; #header; #payload;

    constructor( error, header, payload )
    {
        this.#error = error;
		this.#header = Object.freeze( header );
        this.#payload = Object.freeze( payload );
    }

    get ok(){ return !this.#error }
    get error(){ return this.#error }
    get header(){ return this.#header }
    get payload(){ return this.#payload }
    get claims(){ return this.payload }
    get remaining(){ return this.#payload.exp ? Math.max( 0, this.#payload.exp - Math.ceil( Date.now() / 1000 )) : Infinity }
}

module.exports = class JWT
{
    constructor( algorithms )
    {
        this.algorithms = algorithms;
        this.algorithm = ALGORITHMS.find( a => algorithms[a] );

        /*for( let algorithm in algorithms )
        {
            if( algorithms[algorithm].key )
            {
                let key = crypto.createSecretKey( algorithm[algorithms].key );
            }
        }*/
    }

    create( payload, algorithm, options = {})
    {
        if( typeof algorithm === 'object' ){ options = algorithm; algorithm = undefined; }
        algorithm = algorithm || this.algorithm;

        payload = { ...payload, iat: Math.floor( Date.now() / 1000 )};

        if( options.starts ){ payload.nbf = timestamp(  options.starts )}
        if( options.expires ){ payload.exp = timestamp(  options.expires )}

        let message = encode({ alg: algorithm, typ: 'JWT' }) + '.' + encode( payload ), bits = algorithm.substr(2);

        if( algorithm[0] === 'H' )
        {
            let hmac = crypto.createHmac( 'sha' + bits, this.algorithms[algorithm] );

            return message + '.' + toBase64URL( hmac.update( message ).digest('base64'));
        }
        else
        {
            let sign = crypto.createSign( 'SHA' + bits );

            return message + '.' + toBase64URL( sign.update( message ).sign( this.algorithms[algorithm], 'base64' ));
        }
    }

    parse( jwt )
    {
        try
        {
            let [ header, payload, signature ] = jwt.split('.');

            header = decode( header );
            payload = decode( payload );

            if( header.alg )
            {
                let bits = header.alg.substr(2), error;

                if( header.alg[0] === 'H' )
                {
                    let hmac = crypto.createHmac( 'sha' + bits, this.algorithms[header.alg] );

                    signature = ( toBase64URL( hmac.update( jwt.substr( 0, jwt.length - signature.length - 1 )).digest('base64')) === signature );
                }
                else
                {
                    let verify = crypto.createVerify( 'SHA' + bits );

                    signature = verify.update( jwt.substr( 0, jwt.length - signature.length - 1 )).verify( this.algorithms[header.alg].pub, signature, 'base64' );
                }

                if( !signature )
                {
                    error = 'unauthorized';
                }
                else if( payload.exp && payload.exp < Math.floor( Date.now() / 1000 ))
                {
                    error = 'expired';
                }
                else if( payload.nbf && payload.nbf > Math.ceil( Date.now() / 1000 ))
                {
                    error = 'inactive';
                }

                return new JSONWebToken( error, header, payload );
            }
        }
        catch(e){}
        
        return new JSONWebToken( 'invalid' );
    }
}
