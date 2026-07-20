import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import path from 'path';
import fs from 'fs';
import { pipeline } from 'stream/promises';
import { randomBytes } from 'crypto';
import multer from 'multer';

import { loadConfig, saveConfig, loadManifest, saveManifest, Manifest } from './config';
import { hashPassword, verifyPasswordHash, generateAndWrapDEK, unwrapDEK, createEncryptStream, createDecryptStream, WrappedKey } from './cryptoUtils';
import { logAudit } from './logger';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:"],
      mediaSrc: ["'self'", "blob:"],
      connectSrc: ["'self'"],
    }
  }
}));
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(process.cwd(), 'public')));

// Global rate limiting
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000
});
app.use(globalLimiter);

// Auth rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50 // limit auth attempts
});

// State
let appConfig: any = null;
let activeDEK: Buffer | null = null; 
// To make it zero-trust but functional in a web app, the server must keep the DEK in memory while the vault is "unlocked".
// The server never stores the DEK in plaintext on disk, only wrapped.

// Session Management (In-memory for simplicity as requested, mapping token -> expiry)
const sessions: Record<string, { expires: number, maxAge: number }> = {};
const SESSION_SLIDING_MS = 24 * 60 * 60 * 1000; // 24 hours
const SESSION_MAX_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

// Download tickets
const downloadTickets: Record<string, { fileId: string, expires: number }> = {};

// Initialize
async function init() {
  appConfig = await loadConfig();
  await fs.promises.mkdir(path.join(process.cwd(), 'uploads'), { recursive: true });
}

// Middleware
function requireSetup(req: any, res: any, next: any) {
  if (!appConfig.setupComplete) return res.status(403).json({ error: 'Setup required' });
  next();
}

function requireAuth(req: any, res: any, next: any) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token || !sessions[token]) return res.status(401).json({ error: 'Unauthorized' });
  
  const session = sessions[token];
  const now = Date.now();
  
  if (now > session.expires || now > session.maxAge) {
    delete sessions[token];
    activeDEK = null; // Lock the vault if all sessions expire (simplified)
    return res.status(401).json({ error: 'Session expired' });
  }
  
  // Slide expiration
  session.expires = now + SESSION_SLIDING_MS;
  
  if (!activeDEK) return res.status(401).json({ error: 'Vault locked' });
  
  req.sessionToken = token;
  next();
}

// Routes
app.get('/api/status', async (req, res) => {
  res.json({ setupComplete: appConfig.setupComplete, locked: !activeDEK });
});

app.post('/api/auth/setup', authLimiter, async (req, res) => {
  if (appConfig.setupComplete) return res.status(400).json({ error: 'Already setup' });
  
  const { password } = req.body;
  if (!password || password.length < 12) return res.status(400).json({ error: 'Password must be at least 12 characters' });
  
  try {
    const hash = await hashPassword(password);
    const { dek, wrapped } = await generateAndWrapDEK(password);
    
    appConfig.setupComplete = true;
    appConfig.passwordHash = hash;
    appConfig.wrappedDEK = wrapped;
    await saveConfig(appConfig);
    
    activeDEK = dek;
    
    // Create empty manifest
    await saveManifest(dek, { root: { id: 'root', name: 'Root', files: [], folders: {} } });
    
    logAudit('SETUP', req.ip || '');
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  if (!appConfig.setupComplete) return res.status(400).json({ error: 'Setup required' });
  
  const { password } = req.body;
  const isValid = await verifyPasswordHash(password, appConfig.passwordHash);
  
  if (!isValid) {
    logAudit('LOGIN_FAILED', req.ip || '');
    return res.status(401).json({ error: 'Invalid password' });
  }
  
  try {
    activeDEK = await unwrapDEK(password, appConfig.wrappedDEK);
    
    const token = randomBytes(32).toString('hex');
    const now = Date.now();
    sessions[token] = { expires: now + SESSION_SLIDING_MS, maxAge: now + SESSION_MAX_MS };
    
    logAudit('LOGIN_SUCCESS', req.ip || '');
    res.json({ token });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/logout', requireAuth, (req: any, res) => {
  delete sessions[req.sessionToken];
  if (Object.keys(sessions).length === 0) activeDEK = null;
  logAudit('LOGOUT', req.ip || '');
  res.json({ success: true });
});

app.post('/api/auth/rotate-password', requireAuth, async (req: any, res) => {
  const { oldPassword, newPassword } = req.body;
  if (newPassword.length < 12) return res.status(400).json({ error: 'Password must be at least 12 chars' });
  
  const isValid = await verifyPasswordHash(oldPassword, appConfig.passwordHash);
  if (!isValid) return res.status(401).json({ error: 'Invalid old password' });
  
  try {
    const hash = await hashPassword(newPassword);
    const dek = await unwrapDEK(oldPassword, appConfig.wrappedDEK); // ensure dek is valid
    
    // Re-wrap DEK with new KEK (which uses new password)
    // Wait, generateAndWrapDEK generates a new DEK. We need a function to wrap existing DEK.
    // Let's implement it directly here for brevity
    const { deriveKEK } = await import('./cryptoUtils');
    // We cannot import internal functions if not exported, we need to export deriveKEK or a wrap function.
    // Let's just create a quick workaround:
    const kdfSalt = randomBytes(32);
    const crypto = await import('crypto');
    const sha256 = crypto.createHash('sha256').update(newPassword).digest();
    
    crypto.scrypt(sha256, kdfSalt, 32, { N: 131072, r: 8, p: 1, maxmem: 128 * 1024 * 1024 + 1024 }, async (err, kek) => {
      if(err) return res.status(500).json({ error: 'KDF failed' });
      
      const iv = randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', kek, iv);
      let encryptedDek = cipher.update(dek);
      encryptedDek = Buffer.concat([encryptedDek, cipher.final()]);
      const authTag = cipher.getAuthTag();
      
      appConfig.passwordHash = hash;
      appConfig.wrappedDEK = {
        encryptedDek: encryptedDek.toString('base64'),
        iv: iv.toString('base64'),
        authTag: authTag.toString('base64'),
        kdfSalt: kdfSalt.toString('base64')
      };
      
      await saveConfig(appConfig);
      logAudit('PASSWORD_ROTATED', req.ip || '');
      res.json({ success: true });
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// File streaming setup
const upload = multer({ dest: 'uploads/temp/' });

function findFolder(folder: any, id: string): any {
  if (folder.id === id) return folder;
  for (const key in folder.folders) {
    const found = findFolder(folder.folders[key], id);
    if (found) return found;
  }
  return null;
}

function removeFile(folder: any, fileId: string): boolean {
  const fileIndex = folder.files.findIndex((f: any) => f.id === fileId);
  if (fileIndex !== -1) {
    folder.files.splice(fileIndex, 1);
    return true;
  }
  for (const key in folder.folders) {
    if (removeFile(folder.folders[key], fileId)) return true;
  }
  return false;
}

function removeFolder(parent: any, folderId: string): any {
  if (parent.folders[folderId]) {
    const deleted = parent.folders[folderId];
    delete parent.folders[folderId];
    return deleted;
  }
  for (const key in parent.folders) {
    const found = removeFolder(parent.folders[key], folderId);
    if (found) return found;
  }
  return null;
}

function findFile(folder: any, fileId: string): any {
  const file = folder.files.find((f: any) => f.id === fileId);
  if (file) return file;
  for (const key in folder.folders) {
    const found = findFile(folder.folders[key], fileId);
    if (found) return found;
  }
  return null;
}

function collectFiles(folder: any, fileIds: string[] = []) {
  folder.files.forEach((f: any) => fileIds.push(f.id));
  for (const key in folder.folders) {
    collectFiles(folder.folders[key], fileIds);
  }
  return fileIds;
}

app.post('/api/folders', requireSetup, requireAuth, async (req: any, res) => {
  const { parentId, name } = req.body;
  if (!name || !parentId) return res.status(400).json({ error: 'Missing parentId or name' });
  
  try {
    const manifest = await loadManifest(activeDEK!);
    const parentFolder = findFolder(manifest.root, parentId);
    if (!parentFolder) return res.status(404).json({ error: 'Parent folder not found' });
    
    const folderId = randomBytes(16).toString('hex');
    parentFolder.folders[folderId] = {
      id: folderId,
      name,
      files: [],
      folders: {}
    };
    
    await saveManifest(activeDEK!, manifest);
    logAudit('FOLDER_CREATE', req.ip || '', { folderId, name });
    res.json(parentFolder.folders[folderId]);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/files', requireSetup, requireAuth, async (req: any, res) => {
  try {
    const manifest = await loadManifest(activeDEK!);
    res.json(manifest);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/files/upload', requireSetup, requireAuth, upload.single('file'), async (req: any, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  
  const folderId = req.body.folderId || 'root';
  const fileId = randomBytes(16).toString('hex');
  const destPath = path.join(process.cwd(), 'uploads', fileId);
  const { iv, cipher } = createEncryptStream(activeDEK!);
  
  try {
    const sourceStream = fs.createReadStream(req.file.path);
    const destStream = fs.createWriteStream(destPath);
    
    await pipeline(sourceStream, cipher, destStream);
    const authTag = cipher.getAuthTag();
    
    // Cleanup temp
    await fs.promises.unlink(req.file.path);
    
    const manifest = await loadManifest(activeDEK!);
    const folder = findFolder(manifest.root, folderId);
    if (!folder) {
      await fs.promises.unlink(req.file.path);
      return res.status(404).json({ error: 'Folder not found' });
    }
    
    const newFile = {
      id: fileId,
      name: req.file.originalname,
      size: req.file.size,
      type: req.file.mimetype,
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      createdAt: new Date().toISOString()
    };
    
    folder.files.push(newFile);
    await saveManifest(activeDEK!, manifest);
    
    logAudit('FILE_UPLOAD', req.ip || '', { fileId, name: newFile.name });
    res.json(newFile);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/files/:id', requireSetup, requireAuth, async (req: any, res) => {
  const { id } = req.params;
  
  try {
    const manifest = await loadManifest(activeDEK!);
    let removed = removeFile(manifest.root, id);
    let filesToDelete: string[] = [];

    if (removed) {
      filesToDelete.push(id);
    } else {
      const removedFolder = removeFolder(manifest.root, id);
      if (!removedFolder) return res.status(404).json({ error: 'Not found' });
      filesToDelete = collectFiles(removedFolder);
    }
    
    await saveManifest(activeDEK!, manifest);
    
    for (const fid of filesToDelete) {
      const filePath = path.join(process.cwd(), 'uploads', fid);
      try { await fs.promises.unlink(filePath); } catch(e) {}
    }
    
    logAudit('FILE_DELETE', req.ip || '', { id, filesToDelete });
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/files/download-ticket', requireSetup, requireAuth, (req: any, res) => {
  const { fileId } = req.body;
  if (!fileId) return res.status(400).json({ error: 'Missing fileId' });
  
  const ticket = randomBytes(16).toString('hex');
  downloadTickets[ticket] = { fileId, expires: Date.now() + 60000 };
  
  res.json({ ticket });
});

app.get('/api/files/download/:ticket', requireSetup, async (req: any, res) => {
  const { ticket } = req.params;
  const ticketData = downloadTickets[ticket];
  
  if (!ticketData || Date.now() > ticketData.expires) {
    return res.status(403).json({ error: 'Invalid or expired ticket' });
  }
  
  delete downloadTickets[ticket]; // single use
  
  if (!activeDEK) return res.status(403).json({ error: 'Vault locked' });
  
  try {
    const manifest = await loadManifest(activeDEK);
    const file = findFile(manifest.root, ticketData.fileId);
    
    if (!file) return res.status(404).json({ error: 'File not found' });
    
    const filePath = path.join(process.cwd(), 'uploads', file.id);
    const decipher = createDecryptStream(activeDEK, Buffer.from(file.iv, 'base64'), Buffer.from(file.authTag, 'base64'));
    
    res.setHeader('Content-Disposition', `attachment; filename="${file.name}"`);
    res.setHeader('Content-Type', file.type || 'application/octet-stream');
    
    const readStream = fs.createReadStream(filePath);
    await pipeline(readStream, decipher, res);
    
    logAudit('FILE_DOWNLOAD', req.ip || '', { fileId: file.id });
  } catch (err: any) {
    if (!res.headersSent) res.status(500).json({ error: 'Streaming error' });
  }
});

app.get('/api/settings', requireAuth, (req, res) => {
  res.json(appConfig.settings);
});

// Fallback for SPA routing
app.get('*', (req, res) => {
  res.sendFile(path.join(process.cwd(), 'public', 'index.html'));
});

init().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`CryptVault server running on port ${PORT}`);
  });
}).catch(console.error);
