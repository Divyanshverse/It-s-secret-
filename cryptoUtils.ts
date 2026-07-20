import crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const KDF_SALT_SIZE = 32;
const IV_SIZE = 12;
const AUTH_TAG_SIZE = 16;
const SCRYPT_PARAMS = { N: 131072, r: 8, p: 1, maxmem: 128 * 1024 * 1024 + 1024 };

export interface WrappedKey {
  encryptedDek: string;
  iv: string;
  authTag: string;
  kdfSalt: string;
}

export function hashPassword(password: string): Promise<string> {
  return new Promise(async (resolve, reject) => {
    try {
      const bcrypt = await import('bcrypt');
      const sha256 = crypto.createHash('sha256').update(password).digest('hex');
      const hash = await bcrypt.hash(sha256, 12);
      resolve(hash);
    } catch (error) {
      reject(error);
    }
  });
}

export function verifyPasswordHash(password: string, hash: string): Promise<boolean> {
  return new Promise(async (resolve, reject) => {
    try {
      const bcrypt = await import('bcrypt');
      const sha256 = crypto.createHash('sha256').update(password).digest('hex');
      const isValid = await bcrypt.compare(sha256, hash);
      resolve(isValid);
    } catch (error) {
      reject(error);
    }
  });
}

export function deriveKEK(password: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const sha256 = crypto.createHash('sha256').update(password).digest();
    crypto.scrypt(sha256, salt, 32, SCRYPT_PARAMS, (err, derivedKey) => {
      if (err) reject(err);
      else resolve(derivedKey);
    });
  });
}

export async function generateAndWrapDEK(password: string): Promise<{ dek: Buffer; wrapped: WrappedKey }> {
  const dek = crypto.randomBytes(32);
  const kdfSalt = crypto.randomBytes(KDF_SALT_SIZE);
  const kek = await deriveKEK(password, kdfSalt);
  
  const iv = crypto.randomBytes(IV_SIZE);
  const cipher = crypto.createCipheriv(ALGORITHM, kek, iv);
  
  let encryptedDek = cipher.update(dek);
  encryptedDek = Buffer.concat([encryptedDek, cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    dek,
    wrapped: {
      encryptedDek: encryptedDek.toString('base64'),
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      kdfSalt: kdfSalt.toString('base64'),
    }
  };
}

export async function unwrapDEK(password: string, wrapped: WrappedKey): Promise<Buffer> {
  const kdfSalt = Buffer.from(wrapped.kdfSalt, 'base64');
  const kek = await deriveKEK(password, kdfSalt);
  
  const iv = Buffer.from(wrapped.iv, 'base64');
  const authTag = Buffer.from(wrapped.authTag, 'base64');
  const encryptedDek = Buffer.from(wrapped.encryptedDek, 'base64');

  const decipher = crypto.createDecipheriv(ALGORITHM, kek, iv);
  decipher.setAuthTag(authTag);

  let dek = decipher.update(encryptedDek);
  dek = Buffer.concat([dek, decipher.final()]);
  
  return dek;
}

export function createEncryptStream(dek: Buffer) {
  const iv = crypto.randomBytes(IV_SIZE);
  const cipher = crypto.createCipheriv(ALGORITHM, dek, iv);
  return { iv, cipher };
}

export function createDecryptStream(dek: Buffer, iv: Buffer, authTag: Buffer) {
  const decipher = crypto.createDecipheriv(ALGORITHM, dek, iv);
  decipher.setAuthTag(authTag);
  return decipher;
}

export function encryptMetadata(dek: Buffer, metadata: any): { encryptedData: string, iv: string, authTag: string } {
  const iv = crypto.randomBytes(IV_SIZE);
  const cipher = crypto.createCipheriv(ALGORITHM, dek, iv);
  const data = JSON.stringify(metadata);
  
  let encryptedData = cipher.update(data, 'utf8', 'base64');
  encryptedData += cipher.final('base64');
  const authTag = cipher.getAuthTag();
  
  return {
    encryptedData,
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64')
  };
}

export function decryptMetadata(dek: Buffer, encryptedData: string, ivString: string, authTagString: string): any {
  const iv = Buffer.from(ivString, 'base64');
  const authTag = Buffer.from(authTagString, 'base64');
  const decipher = crypto.createDecipheriv(ALGORITHM, dek, iv);
  decipher.setAuthTag(authTag);
  
  let decryptedData = decipher.update(encryptedData, 'base64', 'utf8');
  decryptedData += decipher.final('utf8');
  
  return JSON.parse(decryptedData);
}
