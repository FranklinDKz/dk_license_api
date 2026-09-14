import bcrypt from 'bcryptjs';
import { config } from '../lib/config.js';
import { exec, one } from '../lib/db.js';
import { uuid } from '../lib/security.js';

export async function bootstrapRoot() {
  const existing = await one('SELECT id FROM users WHERE email = ? LIMIT 1', [config.root.email.toLowerCase()]);
  let org = await one('SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1');
  if (!org) {
    const orgId = uuid();
    await exec('INSERT INTO organizations (id, name, slug, is_active) VALUES (?, ?, ?, 1)', [orgId, config.root.orgName, 'sudo-development']);
    org = { id: orgId };
  }

  if (!existing) {
    const passwordHash = await bcrypt.hash(config.root.password, 12);
    await exec(
    `INSERT INTO users (id, organization_id, name, email, password_hash, role, permissions_json, is_active)
     VALUES (?, ?, ?, ?, ?, 'root', ?, 1)`,
    [uuid(), org.id, config.root.name, config.root.email.toLowerCase(), passwordHash, JSON.stringify(['*'])],
  );
    console.log(`[BOOTSTRAP] Usuário root criado: ${config.root.email}`);
  }

  const product = await one('SELECT id, discord_role_id FROM products WHERE organization_id = ? AND code = ? LIMIT 1', [org.id, 'DK_BASE']);
  if (!product) {
    await exec(`INSERT INTO products (id, organization_id, code, name, description, current_version, discord_role_id, is_active) VALUES (?, ?, 'DK_BASE', 'DK Base FiveM', 'Produto inicial. Edite no painel.', '1.0.0', ?, 1)`, [uuid(), org.id, config.discord.defaultProductRoleId || null]);
    console.log('[BOOTSTRAP] Produto DK_BASE criado.');
  }
}
