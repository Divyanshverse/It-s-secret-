import fs from 'fs/promises';
import path from 'path';
import { encryptMetadata, decryptMetadata, WrappedKey } from './cryptoUtils';

const CONFIG_PATH = path.join(process.cwd(), 'config.json');
const MANIFEST_PATH = path.join(process.cwd(), 'uploads', 'manifest.enc');

export interface AppConfig {
  setupComplete: boolean;
  passwordHash?: string;
  wrappedDEK?: WrappedKey;
  settings: {
    host: string;
    port: number;
    maxFileSizeMB: number;
  };
}

export interface FileEntry {
  id: string;
  name: string;
  size: number;
  type: string;
  iv: string;
  authTag: string;
  createdAt: string;
}

export interface FolderEntry {
  id: string;
  name: string;
  files: FileEntry[];
  folders: Record<string, FolderEntry>;
}

export interface Manifest {
  root: FolderEntry;
}

const DEFAULT_CONFIG: AppConfig = {
  setupComplete: false,
  settings: {
    host: '0.0.0.0', // AI Studio requirement
    port: 3000,
    maxFileSizeMB: 5120 // 5GB
  }
};

export async function loadConfig(): Promise<AppConfig> {
  try {
    const data = await fs.readFile(CONFIG_PATH, 'utf8');
    return JSON.parse(data);
  } catch (err: any) {
    if (err.code === 'ENOENT') {
      await saveConfig(DEFAULT_CONFIG);
      return DEFAULT_CONFIG;
    }
    throw err;
  }
}

export async function saveConfig(config: AppConfig): Promise<void> {
  await fs.writeFile(CONFIG_PATH, JSON.stringify(config, null, 2), 'utf8');
}

export async function loadManifest(dek: Buffer): Promise<Manifest> {
  try {
    const data = await fs.readFile(MANIFEST_PATH, 'utf8');
    const { encryptedData, iv, authTag } = JSON.parse(data);
    return decryptMetadata(dek, encryptedData, iv, authTag) as Manifest;
  } catch (err: any) {
    if (err.code === 'ENOENT') {
      const emptyManifest: Manifest = {
        root: { id: 'root', name: 'Root', files: [], folders: {} }
      };
      return emptyManifest;
    }
    throw err;
  }
}

export async function saveManifest(dek: Buffer, manifest: Manifest): Promise<void> {
  const { encryptedData, iv, authTag } = encryptMetadata(dek, manifest);
  await fs.writeFile(MANIFEST_PATH, JSON.stringify({ encryptedData, iv, authTag }, null, 2), 'utf8');
}
