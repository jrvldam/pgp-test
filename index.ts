import { readFile } from 'fs/promises';
import { generateKeys, encryptText, getMessage, decryptText, verfySignatures, generateRSAKeys } from './pgp';
  
const PASSPHRASE = 'Born2BeWild';
const FILE_PATH = './secret';
const USER_IDS = [{ name: 'alfred', email: 'alfred@wayne.com' }];
const CURVE =  'ed25519';

start().then(console.log).then(() => console.log('Done.')).catch(console.error)

async function start() {
  const { privateArmoredKey, publicArmoredKey } = await generateKeys({ userIds: USER_IDS, curve: CURVE, passphrase: PASSPHRASE });

  const fileContent = await readFile(FILE_PATH, 'utf8');

  const encrypted = await encryptText({ text: fileContent, publicArmoredKey, privateArmoredKey, passphrase: PASSPHRASE });

  const message = await getMessage(encrypted);
  const { decrypted, signatures } = await decryptText({ message, publicArmoredKey, privateArmoredKey, passphrase: PASSPHRASE });

  if (await verfySignatures(signatures)) {
    return decrypted.trim();
  }

  throw new Error('Signature could not verified.');
}

rsaFlow().then(console.log).catch(console.error);

async function rsaFlow(): Promise<string> {
  const { publicKey, privateKey } = await generateRSAKeys();
  const fileContent = await readFile(FILE_PATH, 'utf8');
  const encrypted = await encryptText({ text: fileContent, publicArmoredKey: publicKey })

  const message = await getMessage(encrypted);
  const { decrypted } = await decryptText({ message, privateArmoredKey: privateKey })

  return decrypted.trim();
}
