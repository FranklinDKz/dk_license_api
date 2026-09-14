import Fastify from 'fastify';
import { config } from './lib/config.js';
import { db } from './lib/db.js';
import { bootstrapRoot } from './services/bootstrap.js';
import { authRoutes } from './routes/auth.js';
import { adminRoutes } from './routes/admin.js';
import { serviceRoutes } from './routes/service.js';
import { fivemRoutes } from './routes/fivem.js';

const app = Fastify({ logger: true, trustProxy: config.api.trustProxy });

app.addHook('onRequest', async (request, reply) => {
  const origin = request.headers.origin;
  if (origin && origin === config.api.panelOrigin) {
    reply.header('Access-Control-Allow-Origin', origin);
    reply.header('Access-Control-Allow-Credentials', 'true');
    reply.header('Vary', 'Origin');
  }
  reply.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Service-Token');
  reply.header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  reply.header('X-Content-Type-Options', 'nosniff');
  reply.header('X-Frame-Options', 'DENY');
  reply.header('Referrer-Policy', 'no-referrer');
  reply.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (request.method === 'OPTIONS') return reply.code(204).send();
});

app.get('/', async () => ({
  ok: true,
  service: 'dk-license-api',
  version: '1.6.0',
  health: '/health'
}));

app.get('/health', async () => {
  await db.query('SELECT 1');
  return { ok: true, service: 'dk-license-api', time: new Date().toISOString() };
});

app.get('/api/v1/public/info', async () => ({ ok: true, name: 'DK License Platform', version: '1.6.0' }));

await authRoutes(app);
await adminRoutes(app);
await serviceRoutes(app);
await fivemRoutes(app);

app.setErrorHandler((error, request, reply) => {
  request.log.error(error);
  if (reply.sent) return;
  reply.code(error.statusCode || 500).send({ ok: false, error: 'INTERNAL_ERROR', message: process.env.NODE_ENV === 'production' ? 'Erro interno.' : error.message });
});


async function columnExists(table, column) {
  const [rows] = await db.query(`
    SELECT COUNT(*) AS total
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = ?
      AND COLUMN_NAME = ?
  `, [table, column]);
  return Number(rows?.[0]?.total || 0) > 0;
}

async function ensureDatabaseCompatibility() {
  let addedDiscordRoleColumn = false;
  if (!(await columnExists('license_keys', 'key_ciphertext'))) {
    console.log('[DB] Atualizando banco: adicionando license_keys.key_ciphertext...');
    await db.query(`ALTER TABLE license_keys ADD COLUMN key_ciphertext TEXT NULL AFTER key_last4`);
  }

  if (!(await columnExists('customers', 'access_level'))) {
    console.log('[DB] Atualizando banco: adicionando customers.access_level...');
    await db.query(`ALTER TABLE customers ADD COLUMN access_level ENUM('client','admin') NOT NULL DEFAULT 'client' AFTER status`);
  }

  if (!(await columnExists('products', 'discord_role_id'))) {
    console.log('[DB] Atualizando banco: adicionando products.discord_role_id...');
    await db.query(`ALTER TABLE products ADD COLUMN discord_role_id VARCHAR(32) NULL AFTER current_version`);
    addedDiscordRoleColumn = true;
  }

  await db.query(`
    CREATE TABLE IF NOT EXISTS discord_role_grants (
      id CHAR(36) PRIMARY KEY,
      organization_id CHAR(36) NOT NULL,
      product_id CHAR(36) NOT NULL,
      license_id CHAR(36) NOT NULL,
      discord_id VARCHAR(32) NOT NULL,
      role_id VARCHAR(32) NOT NULL,
      status ENUM('pending','failed','granted') NOT NULL DEFAULT 'pending',
      attempts INT NOT NULL DEFAULT 0,
      last_error TEXT NULL,
      granted_at DATETIME NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      UNIQUE KEY uq_role_grant_license_role (license_id, role_id),
      INDEX idx_role_grant_status (organization_id, status, updated_at),
      CONSTRAINT fk_role_grant_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
      CONSTRAINT fk_role_grant_product FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
      CONSTRAINT fk_role_grant_license FOREIGN KEY (license_id) REFERENCES licenses(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);

  if (addedDiscordRoleColumn && config.discord.defaultProductRoleId) {
    await db.query(`UPDATE products SET discord_role_id=? WHERE discord_role_id IS NULL OR discord_role_id=''`, [config.discord.defaultProductRoleId]);
  }

  // Garante que clientes que já tinham uma licença ativa antes da atualização
  // também entrem na fila do cargo configurado para o produto.
  await db.query(`
    INSERT IGNORE INTO discord_role_grants
      (id, organization_id, product_id, license_id, discord_id, role_id, status)
    SELECT UUID(), l.organization_id, l.product_id, l.id, c.discord_id, p.discord_role_id, 'pending'
      FROM licenses l
      JOIN customers c ON c.id=l.customer_id
      JOIN products p ON p.id=l.product_id
     WHERE l.status='active'
       AND (l.license_type='permanent' OR l.expires_at IS NULL OR l.expires_at > NOW())
       AND c.discord_id IS NOT NULL AND c.discord_id<>''
       AND p.discord_role_id IS NOT NULL AND p.discord_role_id<>''
  `);

  console.log('[DB] Compatibilidade do banco v1.6.0 verificada.');
}

try {
  await db.query('SELECT 1');
  await ensureDatabaseCompatibility();
  await bootstrapRoot();
  await app.listen({ host: config.api.host, port: config.api.port });
  console.log(`DK License API: ${config.api.publicUrl}`);
} catch (error) {
  app.log.error(error);
  process.exit(1);
}

async function shutdown(signal) {
  app.log.info(`${signal}: encerrando...`);
  await app.close();
  await db.end();
  process.exit(0);
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
