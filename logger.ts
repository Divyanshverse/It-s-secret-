import fs from 'fs/promises';
import path from 'path';

const LOG_DIR = path.join(process.cwd(), 'logs');

async function ensureLogDir() {
  try {
    await fs.mkdir(LOG_DIR, { recursive: true });
  } catch (err) {
    // ignore
  }
}

function getLogFileName() {
  const date = new Date().toISOString().split('T')[0];
  return path.join(LOG_DIR, `audit-${date}.log`);
}

export async function logAudit(event: string, ip: string, details: any = {}) {
  await ensureLogDir();
  const timestamp = new Date().toISOString();
  const logEntry = JSON.stringify({ timestamp, event, ip, details }) + '\n';
  
  try {
    await fs.appendFile(getLogFileName(), logEntry, 'utf8');
  } catch (err) {
    console.error('Failed to write to audit log', err);
  }
}
