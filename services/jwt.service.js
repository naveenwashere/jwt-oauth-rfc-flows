let fs = require('fs');
let atob = require('atob');
let jose = require('node-jose');
let jwt = require('jsonwebtoken');

const newline = '\n';

const accesTokenHeaders = {
  algorithm: 'RS256',
  expiresIn: 60 * 15 //Token expiry set to 15 mins
};

const refreshTokenHeaders = {
  algorithm: 'RS256',
  expiresIn: 31556952 //Token expiry set to 1 year
};

const rsaEncKey =
  {
    keys: [
      {
        kty: 'RSA',
        kid: 'jwt-#ncrypt!0n-k#y',
        e: 'AQAB',
        n: 'h7UdoNmAjqIlEUs564SwCQTFgZxqZsnsqJaJU1XOhzPLfmfYa-EDAO1NNxtEtB-BkoRKJFg_gH8ptlphxXddYFM-omZvol9mkTIFWArzJvq1sS6NJE1skzTzoRAOkcxyNFrSu0B28xvXANrstiAH5lsbt8_QkeL2q6XhcXmAzK4w6D--Mzq0qg0zyyEUNIkyZZCBxw0YiJ28qEyhzOk3w_ZV5tlyxYWS7VaGsekQF6rF-WiQZtDS0wmZUF3ygyUIswWaOUnw9Iy3tnrC7HZqzSOQr6njRusmeEk6A2GPpbm7MxC8uRK30spEB1rACc2DNCQr-dIH9o-jv0g0Evhuxw',
        d: 'CuVh4Z5VEh62tzLBDcXzlGXLreJvMJ2Z4NdlY0mKcZSZDCcuW0sPwK1M-9W2qHe3IZp5kX18a8bKBJgxLXeuCaPlbYioAfOC-rl3cGBAsaqDmBxSvM1yoEcqII53fQFbUhTQwrQkWNStaKYrR1w_BiHekd2fs3bzs0h4V3IYA1cDKBOXz8ph5tqKIPskNMyyGqgNcTeakvRT-r5XLLjOje4pl0_bDyAvmnXbOxRAhSSRkTNH8f6iGf4QPHQ8UnkXKUS0XodbYxloM0GxkfO1oKD9vouAklUahz1okvYBCgbi0V-V4vMiISGjQ33f54oFmiNbzyiAPFkEtF2-mnOL4Q',
        p: 'wF58ZKLSWs3qKD69J8A8CLNZqNSjOXE_lP73pG3aB0XL1vU0sndAwGP6MC55oE-jB3v3mZruDTIKDpwupIxyFESfGLmXBcJqLZxgZ-fF-r1LpMk_mVUJslMASXdPNRb_wZyxAtskn9aqEw9kQ4mAF_0J4ouoMiPoT04H4pFBeLk',
        q: 'tJidHagK2_0yqa-_CYzf8lz4ePIrBl-3Vbrtj_Pubx573PZwML0I2Wncf7lEpL4mXAg_xWcNrV7TQjBqbRDN7NMEP8Kn1JmHFf01qDIRFBh5Ibr1Rzp7u1qDCaIIn6PYMdCjSgqjmwl3pWIpHMj9epTB16jrGvZ_MMNBJZ0-Y38',
        dp: 'Zoy4MYnfK8sj7epsOhmvp0-9F1Sr4v5tT8eQStbI6SGbJe-39P-_xBBIGpFcA0sQ9PdwKjG-f8hSNjGqZ8v7MLTYP30IdmiK49--QQX8s8tf3Ovv_JSpw6eduoxg7ENjelpGvugGITN1nQ2SfLJ7V85sC5o5wukDeet2JqEazvk',
        dq: 'l4Yw1TAoJFn1xw-w_sdXItfEll3BobBvd5vGNPDazhrKnCOdEBebNCexHO0KXhs4viEhuHP1stAL-s36jZX64UhPmVuuSx-hit6PxZZ0Y-MAxz9BCslUBWc06MEt8RucindeegIhMTSpUXbhvcgZfV8QoOyWjmHhZ717jJ65OOs',
        qi: 'ZFDIuANTtB3WKLgFp42YJGu548kvyuINMwuXRCavnSmKPuom2cqY4zzouhAjDlPyf9yrjOZQC4UdAsvXZVnO66HPyDLXlwSKmZjf7-iVNWMiJo0ORu-ugR-Bru4feVgGCcehuLivZA9D4M5vA0p6Nk7UBqssSaYJLql0dLk2xvA'
      }
    ]
  };

let encKeystore = jose.JWK.createKeyStore();

function generateEncryptionKeys() {
  return jose.JWK.asKeyStore(rsaEncKey)
    .then((result) => {
      encKeystore = result;
      console.log('Keys generated and loaded...');
    }).catch(error => {
      console.log('Error loading Encryption keys: ', error);
    })
}

//Generated for signatures using: https://rietta.com/blog/2012/01/27/openssl-generating-rsa-key-from-command/
const privateSignKey = {
  key: fs.readFileSync('./sign_tokens/private.pem'),
  passphrase: 'shopback'
};

const publicSignKey = {
  key: fs.readFileSync('./sign_tokens/public.pem'),
  passphrase: 'shopback'
};

generateEncryptionKeys();

const encOptions = {
  format: 'compact',
  contentAlg: 'A128CBC-HS256'
};


const sign = (payload, tokenType) => {
  console.log('Payload received: ' + JSON.stringify(payload) + newline);
  payload['issuedAt'] = new Date().getTime() / 1000;
  console.log('Payload attributes added: ' + JSON.stringify(payload) + newline);
  if (tokenType === 'access_token') {
    return jwt.sign(payload, privateSignKey, accesTokenHeaders);
  }
  return jwt.sign(payload, privateSignKey, refreshTokenHeaders);
};

//Now encrypt the entire token
function encrypt(key, plaintext) {
  return jose.JWE.createEncrypt(encOptions, key)
    .update(plaintext)
    .final()
    .then(result => {
      console.log('Encrypted JW Token: \n' + result + newline);
      return result;
    }, error => {
      console.log('Error encrypting the token: ', error);
    });
}

function signAndEncrypt(payload) {
  const jwtoken = sign(payload);
  return encrypt(encKeystore.toJSON().keys[0], JSON.stringify(jwtoken));
}

const verify = (decrypted, tokenType) => {
  return new Promise((resolve, reject) => {
    jwt.verify(decrypted.replace(/"/g, ''), publicSignKey.key, tokenType === 'access_token' ? accesTokenHeaders : refreshTokenHeaders, function (err, decoded) {
      if (err != null) {
        console.log('Error verifying the token signature: ', err.name, err.message);
        reject(err.name + ' - ' + err.msg);
      }
      console.log(decoded);
      resolve({
        isValid: true,
        nakedToken: decoded
      });
    });
  });
};

function decryptAndVerify(jwtToken, tokenType) {
  console.log("Token received: \n", jwtToken);
  return jose.JWE.createDecrypt(encKeystore)
    .decrypt(jwtToken)
    .then(decrypted => {
      console.log('Decrypted data: ', decrypted.payload);
      return verify(atob(jose.util.base64url.encode(decrypted.payload).replace(/"/g, '')), tokenType);
    }).catch(error => {
      console.log('Error decrypting and verifying the token: ', error);
      return false;
    });
}

module.exports = {
  signAndEncrypt: signAndEncrypt,
  decryptAndVerify: decryptAndVerify
};