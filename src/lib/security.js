import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { config } from './config.js';

export const uuid = () => crypto.randomUUID();
export const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');
export const sha256 = (value) => crypto.createHash('sha256').update(String(value)).digest('hex');
export const hashLicenseKey = (key) => sha256(`${key}:${config.security.licensePepper}`);
export const hashSessionToken = (token) => sha256(`${token}:session:${config.security.licensePepper}`);

function licenseEncryptionKey() {
  return crypto.createHash('sha256')
    .update(`dk-license-key:v1:${config.security.licensePepper}`)
    .digest();
}

export function encryptLicenseKey(plainKey) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', licenseEncryptionKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(String(plainKey), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [iv, tag, ciphertext].map((part) => part.toString('base64url')).join('.');
}

export function decryptLicenseKey(payload) {
  if (!payload) return null;
  try {
    const [ivRaw, tagRaw, cipherRaw] = String(payload).split('.');
    if (!ivRaw || !tagRaw || !cipherRaw) return null;
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      licenseEncryptionKey(),
      Buffer.from(ivRaw, 'base64url'),
    );
    decipher.setAuthTag(Buffer.from(tagRaw, 'base64url'));
    const plain = Buffer.concat([
      decipher.update(Buffer.from(cipherRaw, 'base64url')),
      decipher.final(),
    ]);
    return plain.toString('utf8');
  } catch {
    return null;
  }
}

export const constantEqual = (a, b) => {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
};

export function generateLicenseKey(productCode = 'DK') {
  const prefix = String(productCode).replace(/[^A-Z0-9]/gi, '').toUpperCase().slice(0, 8) || 'DK';
  const blocks = Array.from({ length: 4 }, () => crypto.randomBytes(3).toString('hex').toUpperCase());
  return `DKP-${prefix}-${blocks.join('-')}`;
}

export function publicLicenseId() {
  const n = crypto.randomInt(100000, 999999);
  return `DK-${n}`;
}

export function signAdminToken(user) {
  return jwt.sign(
    { sub: user.id, org: user.organization_id, role: user.role, email: user.email },
    config.security.jwtSecret,
    { expiresIn: `${config.security.adminSessionHours}h`, issuer: 'dk-license-api', audience: 'dk-license-panel' },
  );
}

export function verifyAdminToken(token) {
  return jwt.verify(token, config.security.jwtSecret, {
    issuer: 'dk-license-api',
    audience: 'dk-license-panel',
  });
}

export function normalizeIp(input) {
  if (!input) return '';
  let ip = String(input).trim();
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  if (ip === '::1') ip = '127.0.0.1';
  return ip;
}

export function parseCookie(header = '') {
  return Object.fromEntries(
    header.split(';').map((x) => x.trim()).filter(Boolean).map((part) => {
      const i = part.indexOf('=');
      return i === -1 ? [part, ''] : [part.slice(0, i), decodeURIComponent(part.slice(i + 1))];
    }),
  );
}

export function safeJson(value, fallback = {}) {
  try {
    if (value == null) return fallback;
    return typeof value === 'string' ? JSON.parse(value) : value;
  } catch {
    return fallback;
  }
}
