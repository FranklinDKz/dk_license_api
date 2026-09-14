import mysql from 'mysql2/promise';
import { config } from './config.js';

const ssl = config.db.ssl
  ? {
      rejectUnauthorized: config.db.sslRejectUnauthorized,
      ...(config.db.sslCaBase64
        ? { ca: Buffer.from(config.db.sslCaBase64, 'base64').toString('utf8') }
        : {}),
    }
  : undefined;

export const db = mysql.createPool({
  host: config.db.host,
  port: config.db.port,
  user: config.db.user,
  password: config.db.password,
  database: config.db.database,
  waitForConnections: true,
  connectionLimit: config.db.connectionLimit,
  queueLimit: 0,
  charset: 'utf8mb4',
  timezone: 'Z',
  decimalNumbers: true,
  ...(ssl ? { ssl } : {}),
});

export async function one(sql, params = []) {
  const [rows] = await db.execute(sql, params);
  return rows[0] || null;
}

export async function many(sql, params = []) {
  const [rows] = await db.execute(sql, params);
  return rows;
}

export async function exec(sql, params = []) {
  const [result] = await db.execute(sql, params);
  return result;
}
