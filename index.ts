import * as pgp from 'openpgp';
  
const PASSPHRASE = 'batman';

generate().then(() => console.log('Done.')).catch(console.error);

async function generate() {
  const { privateKey, publicKey } = await pgp.generateKey({
    userIDs: [{ name: 'name', email: 'test@example.com' }],
    curve: 'ed25519',
    passphrase: PASSPHRASE,
  });

  console.log('Private key:', privateKey);
  console.log('Public key:', publicKey);

  return null;
}
