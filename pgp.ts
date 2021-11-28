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
  privateArmoredKey: string;
  passphrase: string;
}): Promise<string> {
  const publicKey = await readKey({ armoredKey: publicArmoredKey });
  const privateKey = await decryptKey({
    privateKey: await readPrivateKey({ armoredKey: privateArmoredKey }),
    passphrase,
  });

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
  publicArmoredKey,
  privateArmoredKey,
  passphrase,
}: {
  message: Message<string>;
  publicArmoredKey: string;
  privateArmoredKey: string;
  passphrase: string;
}): Promise<{ decrypted: string; signatures: VerificationResult[] }> {
  const publicKey = await readKey({ armoredKey: publicArmoredKey });
  const privateKey = await decryptKey({
    privateKey: await readPrivateKey({ armoredKey: privateArmoredKey }),
    passphrase,
  });
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
