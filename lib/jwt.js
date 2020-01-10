'use strict';

const crypto = require('crypto');

const ALGORITHMS = [ 'ES512', 'ES384', 'ES256', 'RS512', 'RS384', 'RS256', 'HS512', 'HS384', 'HS256' /*, 'PS256', 'PS384' */ ];
const INTERVALS = { ms: 1 / 1000, s : 1, m: 60, h: 60 * 60, d: 24 * 60 * 60, w: 7 * 24 * 60 * 60, y: 365 * 24 * 60 * 60 };
const MAX_OCTET = 0x80, ENCODED_TAG_SEQ = 0x30, ENCODED_TAG_INT = 0x02;
const EC_PARAM_SIZE = { ES256: 32, ES384: 48, ES512: 66 /* 64 ? 66 */ } // 256, 384, 521 => (( bits / 8 ) | 0 ) + ( bits % 8 === 0 ? 0 : 1 )

const toBase64URL = ( base64 ) => base64.replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
const fromBase64URL = ( base64url ) => base64url.replace(/\-/g,'+').replace(/_/g,'/');
const base64URLencode = ( data ) => toBase64URL( Buffer.from( data, 'utf8' ).toString('base64') );
const base64URLdecode = ( data ) => Buffer.from( fromBase64URL( data ), 'base64' ).toString('utf8');
const encode = ( data ) => base64URLencode( JSON.stringify( data ));
const decode = ( data ) => JSON.parse( base64URLdecode( data ));
const derToJose = ( signature, algorithm ) =>
{
    let paramBytes = EC_PARAM_SIZE[ algorithm ], jose = Buffer.alloc( 2 * paramBytes ), offset = 0, length, padding;

    ++offset; // if( signature[offset++] !== ENCODED_TAG_SEQ ){ return jose }
    if( signature[offset++] >= MAX_OCTET ){ ++offset }
    
    ++offset; // if( signature[offset++] !== ENCODED_TAG_INT ){ return jose }
    padding = paramBytes - ( length = signature[offset++] );
    signature.copy( jose, Math.max( padding, 0 ), offset - Math.min( padding, 0 ), offset += length );

    ++offset; // if( signature[offset++] !== ENCODED_TAG_INT ){ return jose }
    padding = paramBytes - ( length = signature[offset++] );
    signature.copy( jose, paramBytes + Math.max( padding, 0 ), offset - Math.min( padding, 0 ), offset += length );
    
    return jose;
}
const josePadding = ( buffer, offset ) =>
{
    let padding = 0;

    while( offset < buffer.length && buffer[ offset + padding ] === 0 ){ ++padding }
    if( buffer[ offset + padding ] & MAX_OCTET ){ --padding }

    return padding;
}
const joseToDer = ( signature, algorithm ) =>
{
    let paramBytes = EC_PARAM_SIZE[ algorithm ], rPad = josePadding( signature, 0 ), sPad = josePadding( signature, paramBytes );
    let seqLength = 2 * ( paramBytes + 2 ) - rPad - sPad, der = Buffer.alloc(( seqLength >= MAX_OCTET ? 3 : 2 ) + seqLength ), offset = 0;

    der[offset++] = ENCODED_TAG_SEQ;
    der[offset++] = seqLength;

    if( seqLength >= MAX_OCTET ){ der[offset-1] = MAX_OCTET | 1; der[offset++] = seqLength; }

    der[offset++] = ENCODED_TAG_INT; der[offset++] = paramBytes - rPad;
    signature.copy( der, offset - Math.min( rPad, 0 ), Math.max( rPad, 0 ), paramBytes );
    
    offset += paramBytes - rPad;

    der[offset++] = ENCODED_TAG_INT; der[offset++] = paramBytes - sPad;
    signature.copy( der, offset - Math.min( sPad, 0 ), paramBytes + Math.max( sPad, 0 ), 2 * paramBytes );

    return der;
}

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
    constructor( error, header, claims )
    {
        this.ok = !error;
        this.error = error;
		this.header = Object.freeze( header );
        this.claims = Object.freeze( claims );

        Object.freeze( this );
    }

    get payload(){ return this.claims }
    get remaining(){ return this.claims.exp ? Math.max( 0, this.claims.exp - Math.ceil( Date.now() / 1000 )) : Infinity }
}

module.exports = class JWT
{
    #algorithms; #algorithm;

    constructor( algorithms )
    {
        this.#algorithms = algorithms;
        this.#algorithm = ALGORITHMS.find( a => algorithms[a] );

        /*for( let algorithm in algorithms )
        {
            if( algorithms[algorithm].key )
            {
                let key = crypto.createSecretKey( algorithm[algorithms].key );
            }
        }*/
    }

    create( claims, options = {})
    {
        if( typeof options === 'string' ){ options = { algorithm: options }}

        let algorithm = options.algorithm || this.#algorithm;
        let header = { alg: algorithm, typ: 'JWT' };

        if( options.header ){ Object.assign( header, options.header )}

        claims = { ...claims, iat: Math.floor( Date.now() / 1000 )};

        if( options.starts ){ claims.nbf = timestamp(  options.starts )}
        if( options.expires ){ claims.exp = timestamp(  options.expires )}

        let message = encode( header ) + '.' + encode( claims ), bits = algorithm.substr(2);

        if( algorithm[0] === 'H' )
        {
            let hmac = crypto.createHmac( 'sha' + bits, this.#algorithms[algorithm] );

            return message + '.' + toBase64URL( hmac.update( message ).digest('base64'));
        }
        else
        {
            let sign = crypto.createSign( 'RSA-SHA' + bits );
            let signature = sign.update( message ).sign( this.#algorithms[algorithm] );

            if( header.alg[0] === 'E' )
            {
                signature = derToJose( signature, algorithm );
            }

            return message + '.' + toBase64URL( signature.toString( 'base64' ) );
        }
    }

    parse( jwt )
    {
        try
        {
            let [ header, claims, signature ] = jwt.split('.');

            header = decode( header );
            claims = decode( claims );

            if( header.alg )
            {
                let bits = header.alg.substr(2), message = jwt.substr( 0, jwt.length - signature.length - 1 ), error;

                if( header.alg[0] === 'H' )
                {
                    let hmac = crypto.createHmac( 'sha' + bits, this.#algorithms[header.alg] );

                    signature = ( toBase64URL( hmac.update( message ).digest('base64')) === signature );
                }
                else
                {
                    let verify = crypto.createVerify( 'RSA-SHA' + bits ), alg = this.#algorithms[header.alg];

                    signature = Buffer.from( signature, 'base64' );

                    if( header.alg[0] === 'E' )
                    {
                        signature = joseToDer( signature, header.alg );
                    }

                    signature = verify.update( message ).verify( alg.pub || alg.key, signature );
                }

                if( !signature )
                {
                    error = 'unauthorized';
                }
                else if( claims.exp && claims.exp < Math.floor( Date.now() / 1000 ))
                {
                    error = 'expired';
                }
                else if( claims.nbf && claims.nbf > Math.ceil( Date.now() / 1000 ))
                {
                    error = 'inactive';
                }

                return new JSONWebToken( error, header, claims );
            }
        }
        catch(e){}
        
        return new JSONWebToken( 'invalid' );
    }
}
