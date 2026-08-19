import { createHash, createPublicKey, generateKeyPairSync } from 'node:crypto';

const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const privateKeyPem = privateKey.export({
  type: 'pkcs8',
  format: 'pem',
});
const publicJwk = createPublicKey(privateKey).export({ format: 'jwk' });
const keyId = createHash('sha256')
  .update(
    JSON.stringify({ e: publicJwk.e, kty: publicJwk.kty, n: publicJwk.n }),
  )
  .digest('base64url')
  .slice(0, 16);

console.log(`OIDC_KEY_ID=${keyId}`);
console.log(
  `OIDC_PRIVATE_KEY_BASE64=${Buffer.from(privateKeyPem).toString('base64')}`,
);
console.log('\nStore these values in your deployment secret manager.');
console.log('Never commit the private key or paste it into frontend code.');
