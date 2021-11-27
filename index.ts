import { decrypt, generateKey, readPrivateKey, decryptKey, encrypt, readKey, createMessage, readMessage, Message, VerificationResult } from 'openpgp';
import { readFile } from 'fs/promises';
  
const PASSPHRASE = 'Born2BeWild';
const FILE_PATH = './secret';

start().then(console.log).then(() => console.log('Done.')).catch(console.error)

async function start() {
  const { privateArmoredKey, publicArmoredKey } = await generate();
  const content = await readFile(FILE_PATH, 'utf8');
  const token = await encryptText({ text: content, publicArmoredKey, privateArmoredKey });

  const message = await getMessage(token);
  const { decrypted, signatures } = await decryptText({ message, publicArmoredKey, privateArmoredKey });

  if (await verfySignatures(signatures)) {
    return decrypted.trim();
  }

  throw new Error('Signature could not verified.');
}

async function verfySignatures(signatures: VerificationResult[]): Promise<boolean> {
  try {
    await signatures[0].verified;
    return true;
  } catch (reason) {
    console.error('verfySignatures: ', reason);
    return false;
  }
}

async function decryptText({ message, publicArmoredKey, privateArmoredKey }: { message: Message<string>; publicArmoredKey: string; privateArmoredKey: string }): Promise<{ decrypted: string; signatures: VerificationResult[] }> {
  const publicKey = await readKey({ armoredKey: publicArmoredKey }); 
  const privateKey = await decryptKey({
    privateKey: await readPrivateKey({ armoredKey: privateArmoredKey }),
    passphrase: PASSPHRASE,
  });
  const { data, signatures } = await decrypt({
    message,
    decryptionKeys: privateKey,
    verificationKeys: publicKey, // Optional
  });
  
  return { decrypted: data, signatures };
}

async function getMessage(token: string) {
  return readMessage({ armoredMessage: token });
}

async function encryptText({ text, publicArmoredKey, privateArmoredKey }: { text: string; publicArmoredKey: string; privateArmoredKey: string }): Promise<string> {
  const publicKey = await readKey({ armoredKey: publicArmoredKey });
  const privateKey = await decryptKey({
    privateKey: await readPrivateKey({ armoredKey: privateArmoredKey }),
    passphrase: PASSPHRASE,
  });
  const encrypted = await encrypt({
    message: await createMessage({ text }),
    encryptionKeys: publicKey,
    signingKeys: privateKey, // Optional
  });

  return encrypted;
}

async function generate(): Promise<{ privateArmoredKey: string; publicArmoredKey: string }> {
  const { privateKey, publicKey } = await generateKey({
    userIDs: [{ name: 'alfred', email: 'alfred@wayne.com' }],
    curve: 'ed25519',
    passphrase: PASSPHRASE,
  });
    
  return { privateArmoredKey: privateKey, publicArmoredKey: publicKey };
}
