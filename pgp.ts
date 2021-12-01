import {
  EllipticCurveName,
  decrypt,
  generateKey,
  readPrivateKey,
  decryptKey,
  encrypt,
  readKey,
  createMessage,
  readMessage,
  Message,
  VerificationResult,
} from 'openpgp';

export async function generateKeys({
  userIds,
  curve,
  passphrase,
}: {
  userIds: { name?: string; email?: string }[];
  curve?: EllipticCurveName;
  passphrase?: string;
}): Promise<{
  privateArmoredKey: string;
  publicArmoredKey: string;
  revocationCertificate: string;
}> {
  const { privateKey, publicKey, revocationCertificate } = await generateKey({
    userIDs: userIds,
    curve,
    passphrase,
  });

  return {
    privateArmoredKey: privateKey,
    publicArmoredKey: publicKey,
    revocationCertificate,
  };
}

export async function encryptText({
  text,
  publicArmoredKey,
  privateArmoredKey,
  passphrase,
}: {
  text: string;
  publicArmoredKey: string;
  privateArmoredKey?: string;
  passphrase?: string;
}): Promise<string> {
  const publicKey = await readKey({ armoredKey: publicArmoredKey });
  const privateKey = privateArmoredKey 
    ? await decryptKey({
        privateKey: await readPrivateKey({ armoredKey: privateArmoredKey }),
        passphrase,
      })
    : undefined;

  const encrypted = await encrypt({
    message: await createMessage({ text }),
    encryptionKeys: publicKey,
    signingKeys: privateKey, // Optional
  });

  return encrypted;
}

export async function getMessage(token: string) {
  return readMessage({ armoredMessage: token });
}

export async function decryptText({
  message,
  privateArmoredKey,
  passphrase,
  publicArmoredKey,
}: {
  message: Message<string>;
  privateArmoredKey: string;
  passphrase?: string;
  publicArmoredKey?: string;
}): Promise<{ decrypted: string; signatures?: VerificationResult[] }> {
  const publicKey = publicArmoredKey
    ? await readKey({ armoredKey: publicArmoredKey })
    : undefined;
  const privateKey = passphrase
    ? await decryptKey({
        privateKey: await readPrivateKey({ armoredKey: privateArmoredKey }),
        passphrase,
      })
    : await readPrivateKey({ armoredKey: privateArmoredKey });

  const { data, signatures } = await decrypt({
    message,
    decryptionKeys: privateKey,
    verificationKeys: publicKey, // Optional
  });

  return { decrypted: data, signatures };
}

export async function verfySignatures(
  signatures: VerificationResult[],
): Promise<boolean> {
  try {
    await signatures[0].verified;
    return true;
  } catch (reason) {
    console.error('verfySignatures: ', reason);
    return false;
  }
}

export async function generateRSAKeys(): Promise<{ publicKey: string; privateKey: string }> {
  const { publicKey, privateKey } = await generateKey({
    type: 'rsa',
    rsaBits: 4096,
    userIDs: [{}],
    keyExpirationTime: 60 * 60 * 24 * 365,
  });

  return { publicKey, privateKey };
}
