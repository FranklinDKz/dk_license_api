import bcrypt from 'bcryptjs';
import net from 'node:net';
import { requireAdmin, requireRole } from '../middleware/auth.js';
import { config } from '../lib/config.js';
import { db, exec, many, one } from '../lib/db.js';
import { decryptLicenseKey, encryptLicenseKey, generateLicenseKey, hashLicenseKey, normalizeIp, publicLicenseId, uuid } from '../lib/security.js';
import { approveIpChange, approveRequest, changeLicenseStatus, createLicenseRequest, extendLicense, forceLicenseIp, regenerateKey, rejectRequest, resetLicenseInstances, updateLicenseLimits } from '../services/licenses.js';
import { audit } from '../services/audit.js';

export async function adminRoutes(app) {
  app.addHook('preHandler', async (request, reply) => {
    if (request.url.startsWith('/api/v1/admin/')) await requireAdmin(request, reply);
  });

  app.get('/api/v1/admin/stats', async (request) => {
    const org = request.admin.organization_id;
    const [licenses, pending, customers, security, sessions, blocks] = await Promise.all([
      one(`SELECT COUNT(*) total, SUM(status='active') active, SUM(status='suspended') suspended, SUM(status='revoked') revoked, SUM(status='expired') expired, SUM(expires_at IS NOT NULL AND expires_at BETWEEN NOW() AND DATE_ADD(NOW(), INTERVAL 7 DAY)) expiring_7d, SUM(expires_at IS NOT NULL AND expires_at BETWEEN NOW() AND DATE_ADD(NOW(), INTERVAL 24 HOUR)) expiring_24h FROM licenses WHERE organization_id=?`, [org]),
      one(`SELECT COUNT(*) total FROM license_requests WHERE organization_id=? AND status='pending'`, [org]),
      one(`SELECT COUNT(*) total FROM customers WHERE organization_id=?`, [org]),
      one(`SELECT COUNT(*) total FROM security_events WHERE organization_id=? AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)`, [org]),
      one(`SELECT COUNT(*) total FROM license_sessions s JOIN licenses l ON l.id=s.license_id WHERE l.organization_id=? AND s.status='active'`, [org]),
      one(`SELECT (SELECT COUNT(*) FROM blocked_ips WHERE organization_id=? AND is_active=1) + (SELECT COUNT(*) FROM blocked_discords WHERE organization_id=? AND is_active=1) AS total`, [org, org]),
    ]);
    return { ok: true, stats: { licenses, pending: Number(pending.total), customers: Number(customers.total), security24h: Number(security.total), activeSessions: Number(sessions.total), activeBlocks: Number(blocks.total), expiring24h: Number(licenses.expiring_24h || 0) } };
  });

  app.get('/api/v1/admin/requests', async (request) => ({ ok: true, requests: await many(
    `SELECT lr.*, c.name customer_name, c.email, c.discord_id, p.code product_code, p.name product_name
     FROM license_requests lr JOIN customers c ON c.id=lr.customer_id JOIN products p ON p.id=lr.product_id
     WHERE lr.organization_id=? ORDER BY FIELD(lr.status,'pending','approved','rejected'), lr.created_at DESC LIMIT 300`, [request.admin.organization_id]) }));

  app.post('/api/v1/admin/requests/:id/approve', { preHandler: requireRole('root','owner','admin','support') }, async (request, reply) => {
    const b = request.body || {};
    const result = await approveRequest({ requestId: request.params.id, expectedOrganizationId: request.admin.organization_id, actorUserId: request.admin.id, licenseType: b.licenseType || 'permanent', durationDays: b.durationDays, durationMinutes: b.durationMinutes, maxInstances: b.maxInstances || 1, ipChangeLimit: b.ipChangeLimit, actorIp: request.ip });
    return result.ok ? result : reply.code(result.status || 400).send(result);
  });

  app.post('/api/v1/admin/requests/:id/reject', { preHandler: requireRole('root','owner','admin','support') }, async (request, reply) => {
    const result = await rejectRequest({ requestId: request.params.id, expectedOrganizationId: request.admin.organization_id, actorUserId: request.admin.id, reason: request.body?.reason, actorIp: request.ip });
    return result.ok ? result : reply.code(result.status || 400).send(result);
  });


  app.post('/api/v1/admin/licenses/manual', { preHandler: requireRole('root','owner','admin','reseller') }, async (request, reply) => {
    const b = request.body || {};
    if (!b.discordId || !b.name || !b.email || !b.productCode || !b.requestedIp) return reply.code(400).send({ ok: false, error: 'INVALID_INPUT' });
    const created = await createLicenseRequest({ organizationId: request.admin.organization_id, bypassRequestLimit: true, discordId: String(b.discordId), discordUsername: b.discordUsername || null, name: b.name, email: b.email, productCode: b.productCode, requestedIp: b.requestedIp, notes: b.notes || 'Emissão manual pelo painel', actorIp: request.ip });
    if (!created.ok) return reply.code(created.status || 400).send(created);
    const result = await approveRequest({ requestId: created.request.id, expectedOrganizationId: request.admin.organization_id, actorUserId: request.admin.id, licenseType: b.licenseType || 'permanent', durationDays: b.durationDays, durationMinutes: b.durationMinutes, maxInstances: b.maxInstances || 1, ipChangeLimit: b.ipChangeLimit, actorIp: request.ip });
    return result.ok ? result : reply.code(result.status || 400).send(result);
  });

  app.get('/api/v1/admin/licenses', async (request) => {
    const rows = await many(
      `SELECT l.*, c.name customer_name, c.email, c.discord_id, p.code product_code, p.name product_name,
              lk.key_last4, lk.key_ciphertext, c.access_level AS customer_access_level,
        (SELECT COUNT(*) FROM license_sessions s WHERE s.license_id=l.id AND s.status='active') active_sessions
       FROM licenses l JOIN customers c ON c.id=l.customer_id JOIN products p ON p.id=l.product_id
       LEFT JOIN license_keys lk ON lk.license_id=l.id AND lk.is_active=1
       WHERE l.organization_id=? ORDER BY l.created_at DESC LIMIT 500`,
      [request.admin.organization_id],
    );
    const canViewKeys = ['root', 'owner', 'admin'].includes(request.admin.role);
    return {
      ok: true,
      licenses: rows.map(({ key_ciphertext, ...row }) => ({
        ...row,
        key: canViewKeys ? decryptLicenseKey(key_ciphertext) : null,
        keyRecoverable: !!key_ciphertext,
      })),
    };
  });

  app.post('/api/v1/admin/licenses/:id/status', { preHandler: requireRole('root','owner','admin','support') }, async (request, reply) => {
    const result = await changeLicenseStatus({ licenseId: request.params.id, organizationId: request.admin.organization_id, status: request.body?.status, actorUserId: request.admin.id, actorIp: request.ip });
    return result.ok ? result : reply.code(result.status || 400).send(result);
  });

  app.post('/api/v1/admin/licenses/:id/extend', { preHandler: requireRole('root','owner','admin') }, async (request, reply) => {
    const result = await extendLicense({ licenseId: request.params.id, organizationId: request.admin.organization_id, days: request.body?.days, minutes: request.body?.minutes, permanent: !!request.body?.permanent, actorUserId: request.admin.id, actorIp: request.ip });
    return result.ok ? result : reply.code(result.status || 400).send(result);
  });

  app.post('/api/v1/admin/licenses/:id/regenerate-key', { preHandler: requireRole('root','owner','admin') }, async (request, reply) => {
    const result = await regenerateKey({ licenseId: request.params.id, organizationId: request.admin.organization_id, actorUserId: request.admin.id, actorIp: request.ip });
    return result.ok ? result : reply.code(result.status || 400).send(result);
  });

  app.post('/api/v1/admin/licenses/:id/ip', { preHandler: requireRole('root','owner','admin','support') }, async (request, reply) => {
    const result = await forceLicenseIp({ licenseId:request.params.id, organizationId:request.admin.organization_id, newIp:request.body?.newIp, actorUserId:request.admin.id, actorIp:request.ip });
    return result.ok ? result : reply.code(result.status || 400).send(result);
  });

  app.post('/api/v1/admin/licenses/:id/limits', { preHandler: requireRole('root','owner','admin') }, async (request, reply) => {
    const result = await updateLicenseLimits({ licenseId:request.params.id, organizationId:request.admin.organization_id, maxInstances:request.body?.maxInstances, ipChangeLimit:request.body?.ipChangeLimit, actorUserId:request.admin.id, actorIp:request.ip });
    return result.ok ? result : reply.code(result.status || 400).send(result);
  });

  app.post('/api/v1/admin/licenses/:id/reset-instances', { preHandler: requireRole('root','owner','admin','support') }, async (request, reply) => {
    const result = await resetLicenseInstances({ licenseId:request.params.id, organizationId:request.admin.organization_id, actorUserId:request.admin.id, actorIp:request.ip });
    return result.ok ? result : reply.code(result.status || 400).send(result);
  });

  app.get('/api/v1/admin/ip-changes', async (request) => ({ ok: true, requests: await many(
    `SELECT r.*, l.public_id, c.name customer_name, c.discord_id FROM ip_change_requests r JOIN licenses l ON l.id=r.license_id JOIN customers c ON c.id=l.customer_id
     WHERE r.organization_id=? ORDER BY FIELD(r.status,'pending','approved','rejected'), r.created_at DESC LIMIT 300`, [request.admin.organization_id]) }));

  app.post('/api/v1/admin/ip-changes/:id/approve', { preHandler: requireRole('root','owner','admin','support') }, async (request, reply) => {
    const result = await approveIpChange({ requestId: request.params.id, expectedOrganizationId: request.admin.organization_id, actorUserId: request.admin.id, actorIp: request.ip });
    return result.ok ? result : reply.code(result.status || 400).send(result);
  });

  app.get('/api/v1/admin/products', async (request) => ({ ok: true, products: await many('SELECT * FROM products WHERE organization_id=? ORDER BY created_at DESC', [request.admin.organization_id]) }));

  app.post('/api/v1/admin/products', { preHandler: requireRole('root','owner','admin') }, async (request, reply) => {
    const { code, name, description, currentVersion } = request.body || {};
    if (!code || !name) return reply.code(400).send({ ok: false, error: 'INVALID_INPUT' });
    const cleanedCode = String(code).toUpperCase().replace(/[^A-Z0-9_-]/g, '');
    const rawRole = String(request.body?.discordRoleId ?? config.discord.defaultProductRoleId ?? '').trim();
    const discordRoleId = rawRole || null;
    if (discordRoleId && !/^\d{15,25}$/.test(discordRoleId)) return reply.code(400).send({ ok:false, error:'INVALID_DISCORD_ROLE', message:'Informe um ID de cargo Discord válido.' });
    const id = uuid();
    try {
      await exec(`INSERT INTO products (id, organization_id, code, name, description, current_version, discord_role_id, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, 1)`, [id, request.admin.organization_id, cleanedCode, name, description || null, String(currentVersion || '1.0.0').trim() || '1.0.0', discordRoleId]);
      await audit({ organizationId: request.admin.organization_id, actorUserId: request.admin.id, action: 'PRODUCT_CREATED', entityType: 'product', entityId: id, ip: request.ip, metadata: { code: cleanedCode, name, discordRoleId } });
      return { ok: true, id, discordRoleId };
    } catch (e) { return reply.code(409).send({ ok: false, error: 'PRODUCT_CREATE_FAILED', message: e.message }); }
  });

  app.patch('/api/v1/admin/products/:id', { preHandler: requireRole('root','owner','admin') }, async (request, reply) => {
    const product = await one('SELECT * FROM products WHERE id=? AND organization_id=? LIMIT 1', [request.params.id, request.admin.organization_id]);
    if (!product) return reply.code(404).send({ ok:false, error:'NOT_FOUND' });
    const name = String(request.body?.name ?? product.name).trim();
    const description = String(request.body?.description ?? product.description ?? '').trim() || null;
    const currentVersion = String(request.body?.currentVersion ?? product.current_version ?? '1.0.0').trim() || '1.0.0';
    const rawRole = String(request.body?.discordRoleId ?? product.discord_role_id ?? '').trim();
    const discordRoleId = rawRole || null;
    if (!name) return reply.code(400).send({ ok:false, error:'INVALID_INPUT' });
    if (discordRoleId && !/^\d{15,25}$/.test(discordRoleId)) return reply.code(400).send({ ok:false, error:'INVALID_DISCORD_ROLE', message:'Informe um ID de cargo Discord válido.' });
    await exec('UPDATE products SET name=?, description=?, current_version=?, discord_role_id=?, updated_at=CURRENT_TIMESTAMP WHERE id=?', [name, description, currentVersion, discordRoleId, product.id]);
    if (discordRoleId) {
      await exec(
        `INSERT IGNORE INTO discord_role_grants
          (id, organization_id, product_id, license_id, discord_id, role_id, status)
         SELECT UUID(), l.organization_id, l.product_id, l.id, c.discord_id, ?, 'pending'
           FROM licenses l
           JOIN customers c ON c.id=l.customer_id
          WHERE l.organization_id=? AND l.product_id=? AND l.status='active'
            AND (l.license_type='permanent' OR l.expires_at IS NULL OR l.expires_at > NOW())
            AND c.discord_id IS NOT NULL AND c.discord_id<>''`,
        [discordRoleId, request.admin.organization_id, product.id],
      );
    }
    await audit({ organizationId:request.admin.organization_id, actorUserId:request.admin.id, action:'PRODUCT_UPDATED', entityType:'product', entityId:product.id, ip:request.ip, metadata:{ code:product.code, discordRoleId } });
    return { ok:true, product:{ id:product.id, code:product.code, name, description, currentVersion, discordRoleId } };
  });

  app.get('/api/v1/admin/customers', async (request) => ({ ok: true, customers: await many(
    `SELECT c.*, COUNT(l.id) license_count FROM customers c LEFT JOIN licenses l ON l.customer_id=c.id WHERE c.organization_id=? GROUP BY c.id ORDER BY c.created_at DESC LIMIT 500`, [request.admin.organization_id]) }));

  app.get('/api/v1/admin/audit', async (request) => ({ ok: true, logs: await many(
    `SELECT a.*, u.name actor_name FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_user_id WHERE a.organization_id=? ORDER BY a.created_at DESC LIMIT 500`, [request.admin.organization_id]) }));

  app.get('/api/v1/admin/security', async (request) => ({ ok: true, events: await many(
    `SELECT * FROM security_events WHERE organization_id=? ORDER BY created_at DESC LIMIT 500`, [request.admin.organization_id]) }));


  app.get('/api/v1/admin/users', async (request) => ({ ok: true, users: await many(
    `SELECT id, name, email, role, is_active, last_login_at, created_at FROM users WHERE organization_id=? ORDER BY created_at ASC`, [request.admin.organization_id]) }));

  app.post('/api/v1/admin/users', { preHandler: requireRole('root', 'owner') }, async (request, reply) => {
    const { name, email, password, role } = request.body || {};
    const allowedRoles = ['owner','admin','support','reseller','viewer'];
    if (!name || !email || !password || !allowedRoles.includes(role)) return reply.code(400).send({ ok: false, error: 'INVALID_INPUT' });
    if (String(password).length < 10) return reply.code(400).send({ ok: false, error: 'WEAK_PASSWORD', message: 'Use pelo menos 10 caracteres.' });
    try {
      const id = uuid();
      const passwordHash = await bcrypt.hash(String(password), 12);
      await exec(`INSERT INTO users (id, organization_id, name, email, password_hash, role, permissions_json, is_active) VALUES (?, ?, ?, ?, ?, ?, '[]', 1)`, [id, request.admin.organization_id, name, String(email).toLowerCase(), passwordHash, role]);
      await audit({ organizationId: request.admin.organization_id, actorUserId: request.admin.id, action: 'ADMIN_USER_CREATED', entityType: 'user', entityId: id, ip: request.ip, metadata: { email, role } });
      return { ok: true, id };
    } catch (e) { return reply.code(409).send({ ok: false, error: 'USER_CREATE_FAILED', message: e.message }); }
  });

  app.post('/api/v1/admin/users/:id/status', { preHandler: requireRole('root', 'owner') }, async (request, reply) => {
    if (request.params.id === request.admin.id) return reply.code(400).send({ ok: false, error: 'CANNOT_DISABLE_SELF' });
    const target = await one('SELECT id, role FROM users WHERE id=? AND organization_id=? LIMIT 1', [request.params.id, request.admin.organization_id]);
    if (!target) return reply.code(404).send({ ok:false, error:'NOT_FOUND' });
    if (target.role === 'root' && request.admin.role !== 'root') return reply.code(403).send({ ok:false, error:'FORBIDDEN' });
    if (target.role === 'owner' && request.admin.role !== 'root') return reply.code(403).send({ ok:false, error:'FORBIDDEN' });
    const active = request.body?.isActive ? 1 : 0;
    await exec('UPDATE users SET is_active=? WHERE id=? AND organization_id=?', [active, request.params.id, request.admin.organization_id]);
    await audit({ organizationId: request.admin.organization_id, actorUserId: request.admin.id, action: active ? 'ADMIN_USER_ENABLED' : 'ADMIN_USER_DISABLED', entityType: 'user', entityId: request.params.id, ip: request.ip });
    return { ok: true };
  });

  app.post('/api/v1/admin/block-discord', { preHandler: requireRole('root', 'owner', 'admin') }, async (request, reply) => {
    const { discordId, reason } = request.body || {};
    if (!discordId) return reply.code(400).send({ ok:false, error:'INVALID_INPUT' });
    await exec(`INSERT INTO blocked_discords (id, organization_id, discord_id, reason, is_active, created_by_user_id) VALUES (?, ?, ?, ?, 1, ?) ON DUPLICATE KEY UPDATE reason=VALUES(reason), is_active=1`, [uuid(), request.admin.organization_id, String(discordId), reason || null, request.admin.id]);
    await audit({ organizationId:request.admin.organization_id, actorUserId:request.admin.id, action:'DISCORD_BLOCKED', entityType:'discord', entityId:null, ip:request.ip, metadata:{ discordId, reason } });
    return { ok:true };
  });

  app.post('/api/v1/admin/block-ip', { preHandler: requireRole('root', 'owner', 'admin') }, async (request, reply) => {
    const { ip, reason } = request.body || {};
    if (!ip) return reply.code(400).send({ ok: false, error: 'INVALID_INPUT' });
    await exec(`INSERT INTO blocked_ips (id, organization_id, ip_address, reason, is_active, created_by_user_id) VALUES (?, ?, ?, ?, 1, ?) ON DUPLICATE KEY UPDATE reason=VALUES(reason), is_active=1`, [uuid(), request.admin.organization_id, ip, reason || null, request.admin.id]);
    return { ok: true };
  });

  app.get('/api/v1/admin/sessions', async (request) => ({ ok: true, sessions: await many(
    `SELECT s.id, s.license_id, s.instance_uid, s.ip_address, s.status, s.expires_at, s.last_heartbeat_at, s.closed_at, s.created_at,
            l.public_id, l.organization_id, p.code AS product_code, p.name AS product_name,
            c.name AS customer_name, c.discord_id
     FROM license_sessions s
     JOIN licenses l ON l.id=s.license_id
     JOIN products p ON p.id=l.product_id
     JOIN customers c ON c.id=l.customer_id
     WHERE l.organization_id=?
     ORDER BY FIELD(s.status,'active','expired','revoked','closed','replaced'), s.created_at DESC LIMIT 1000`,
    [request.admin.organization_id]) }));

  app.post('/api/v1/admin/sessions/:id/revoke', { preHandler: requireRole('root', 'owner', 'admin', 'support') }, async (request, reply) => {
    const session = await one(`SELECT s.id, s.license_id FROM license_sessions s JOIN licenses l ON l.id=s.license_id WHERE s.id=? AND l.organization_id=? LIMIT 1`, [request.params.id, request.admin.organization_id]);
    if (!session) return reply.code(404).send({ ok:false, error:'NOT_FOUND' });
    await exec(`UPDATE license_sessions SET status='revoked', closed_at=CURRENT_TIMESTAMP WHERE id=?`, [session.id]);
    await audit({ organizationId:request.admin.organization_id, actorUserId:request.admin.id, action:'SESSION_REVOKED', entityType:'license_session', entityId:session.id, ip:request.ip, metadata:{ licenseId:session.license_id } });
    return { ok:true };
  });

  app.get('/api/v1/admin/blocks', async (request) => {
    const [ips, discords] = await Promise.all([
      many(`SELECT * FROM blocked_ips WHERE organization_id=? AND is_active=1 ORDER BY created_at DESC`, [request.admin.organization_id]),
      many(`SELECT * FROM blocked_discords WHERE organization_id=? AND is_active=1 ORDER BY created_at DESC`, [request.admin.organization_id]),
    ]);
    return { ok:true, ips, discords };
  });

  app.post('/api/v1/admin/blocks/ip/:id/unblock', { preHandler: requireRole('root','owner','admin') }, async (request, reply) => {
    const item = await one('SELECT id, ip_address FROM blocked_ips WHERE id=? AND organization_id=? LIMIT 1', [request.params.id, request.admin.organization_id]);
    if (!item) return reply.code(404).send({ ok:false, error:'NOT_FOUND' });
    await exec('UPDATE blocked_ips SET is_active=0 WHERE id=?', [item.id]);
    await audit({ organizationId:request.admin.organization_id, actorUserId:request.admin.id, action:'IP_UNBLOCKED', entityType:'blocked_ip', entityId:item.id, ip:request.ip, metadata:{ ip:item.ip_address } });
    return { ok:true };
  });

  app.post('/api/v1/admin/blocks/discord/:id/unblock', { preHandler: requireRole('root','owner','admin') }, async (request, reply) => {
    const item = await one('SELECT id, discord_id FROM blocked_discords WHERE id=? AND organization_id=? LIMIT 1', [request.params.id, request.admin.organization_id]);
    if (!item) return reply.code(404).send({ ok:false, error:'NOT_FOUND' });
    await exec('UPDATE blocked_discords SET is_active=0 WHERE id=?', [item.id]);
    await audit({ organizationId:request.admin.organization_id, actorUserId:request.admin.id, action:'DISCORD_UNBLOCKED', entityType:'blocked_discord', entityId:item.id, ip:request.ip, metadata:{ discordId:item.discord_id } });
    return { ok:true };
  });

  app.post('/api/v1/admin/audit/cleanup', { preHandler: requireRole('root','owner','admin') }, async (request) => {
    const all = !!request.body?.all;
    const days = Math.max(1, Math.min(3650, Number(request.body?.days || 30)));
    const cutoff = new Date(Date.now() - days * 86400000);
    const result = all
      ? await exec('DELETE FROM audit_logs WHERE organization_id=?', [request.admin.organization_id])
      : await exec('DELETE FROM audit_logs WHERE organization_id=? AND created_at < ?', [request.admin.organization_id, cutoff]);
    await audit({ organizationId:request.admin.organization_id, actorUserId:request.admin.id, action:'AUDIT_LOGS_CLEANED', entityType:'audit', ip:request.ip, metadata:{ all, days, deleted:Number(result.affectedRows||0) } });
    return { ok:true, deleted:Number(result.affectedRows||0) };
  });

  app.post('/api/v1/admin/security/cleanup', { preHandler: requireRole('root','owner','admin') }, async (request) => {
    const all = !!request.body?.all;
    const days = Math.max(1, Math.min(3650, Number(request.body?.days || 30)));
    const cutoff = new Date(Date.now() - days * 86400000);
    const result = all
      ? await exec('DELETE FROM security_events WHERE organization_id=?', [request.admin.organization_id])
      : await exec('DELETE FROM security_events WHERE organization_id=? AND created_at < ?', [request.admin.organization_id, cutoff]);
    await audit({ organizationId:request.admin.organization_id, actorUserId:request.admin.id, action:'SECURITY_LOGS_CLEANED', entityType:'security', ip:request.ip, metadata:{ all, days, deleted:Number(result.affectedRows||0) } });
    return { ok:true, deleted:Number(result.affectedRows||0) };
  });

  app.post('/api/v1/admin/products/:id/status', { preHandler: requireRole('root','owner','admin') }, async (request, reply) => {
    const isActive = request.body?.isActive ? 1 : 0;
    const product = await one('SELECT id, code FROM products WHERE id=? AND organization_id=? LIMIT 1', [request.params.id, request.admin.organization_id]);
    if (!product) return reply.code(404).send({ ok:false, error:'NOT_FOUND' });
    await exec('UPDATE products SET is_active=? WHERE id=?', [isActive, product.id]);
    await audit({ organizationId:request.admin.organization_id, actorUserId:request.admin.id, action:isActive?'PRODUCT_ENABLED':'PRODUCT_DISABLED', entityType:'product', entityId:product.id, ip:request.ip, metadata:{ code:product.code } });
    return { ok:true };
  });

  app.post('/api/v1/admin/users/:id/password', { preHandler: requireRole('root','owner') }, async (request, reply) => {
    const password = String(request.body?.password || '');
    if (password.length < 10) return reply.code(400).send({ ok:false, error:'WEAK_PASSWORD', message:'Use pelo menos 10 caracteres.' });
    const user = await one('SELECT id, email, role FROM users WHERE id=? AND organization_id=? LIMIT 1', [request.params.id, request.admin.organization_id]);
    if (!user) return reply.code(404).send({ ok:false, error:'NOT_FOUND' });
    if (user.role === 'root' && request.admin.role !== 'root') return reply.code(403).send({ ok:false, error:'FORBIDDEN' });
    if (user.role === 'owner' && request.admin.role !== 'root') return reply.code(403).send({ ok:false, error:'FORBIDDEN' });
    const passwordHash = await bcrypt.hash(password, 12);
    await exec('UPDATE users SET password_hash=?, updated_at=CURRENT_TIMESTAMP WHERE id=?', [passwordHash, user.id]);
    await audit({ organizationId:request.admin.organization_id, actorUserId:request.admin.id, action:'ADMIN_PASSWORD_RESET', entityType:'user', entityId:user.id, ip:request.ip, metadata:{ email:user.email } });
    return { ok:true };
  });


  app.patch('/api/v1/admin/customers/:id', { preHandler: requireRole('root','owner','admin') }, async (request, reply) => {
    const b = request.body || {};
    const customer = await one('SELECT * FROM customers WHERE id=? AND organization_id=? LIMIT 1', [request.params.id, request.admin.organization_id]);
    if (!customer) return reply.code(404).send({ ok:false, error:'NOT_FOUND' });

    const name = String(b.name ?? customer.name).trim();
    const email = String(b.email ?? customer.email).trim().toLowerCase();
    const discordId = String(b.discordId ?? customer.discord_id ?? '').trim() || null;
    const discordUsername = String(b.discordUsername ?? customer.discord_username ?? '').trim() || null;
    const status = String(b.status ?? customer.status);
    const accessLevel = String(b.accessLevel ?? customer.access_level ?? 'client').toLowerCase();
    const notes = b.notes == null ? customer.notes : (String(b.notes).trim() || null);

    if (!name || !email || !['active','inactive','blocked'].includes(status) || !['client','admin'].includes(accessLevel)) {
      return reply.code(400).send({ ok:false, error:'INVALID_INPUT' });
    }
    if (accessLevel === 'admin' && !['root','owner'].includes(request.admin.role)) {
      return reply.code(403).send({ ok:false, error:'FORBIDDEN', message:'Somente Root/Owner pode conceder bypass ADMIN.' });
    }

    try {
      await exec(`UPDATE customers SET name=?, email=?, discord_id=?, discord_username=?, status=?, access_level=?, notes=?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND organization_id=?`,
        [name, email, discordId, discordUsername, status, accessLevel, notes, customer.id, request.admin.organization_id]);

      let adminLicense = null;
      if (accessLevel === 'admin') {
        const existing = await one(
          `SELECT l.id, l.public_id, lk.key_ciphertext, lk.key_last4, p.code AS product_code
           FROM licenses l
           JOIN license_keys lk ON lk.license_id=l.id AND lk.is_active=1
           JOIN products p ON p.id=l.product_id
           WHERE l.customer_id=? AND l.organization_id=?
           ORDER BY l.created_at DESC LIMIT 1`,
          [customer.id, request.admin.organization_id],
        );

        if (existing) {
          adminLicense = { publicId: existing.public_id, key: decryptLicenseKey(existing.key_ciphertext), keyLast4: existing.key_last4, productCode: existing.product_code, created: false };
        } else {
          const product = await one(`SELECT * FROM products WHERE organization_id=? AND is_active=1 ORDER BY (code='DK_BASE') DESC, created_at ASC LIMIT 1`, [request.admin.organization_id]);
          if (!product) return reply.code(409).send({ ok:false, error:'NO_PRODUCT', message:'Crie pelo menos um produto antes de ativar um cliente ADMIN.' });

          let publicId;
          do {
            publicId = publicLicenseId();
          } while (await one('SELECT id FROM licenses WHERE public_id=? LIMIT 1', [publicId]));

          const licenseId = uuid();
          const key = generateLicenseKey(product.code);
          await exec(
            `INSERT INTO licenses (id, organization_id, customer_id, product_id, public_id, status, license_type, bound_ip, expires_at, max_instances, ip_change_limit, ip_changes_used, notes)
             VALUES (?, ?, ?, ?, ?, 'active', 'permanent', '0.0.0.0', NULL, 1000, 1000, 0, 'Acesso ADMIN gerado automaticamente pelo painel')`,
            [licenseId, request.admin.organization_id, customer.id, product.id, publicId],
          );
          await exec(
            `INSERT INTO license_keys (id, license_id, key_hash, key_last4, key_ciphertext, is_active, issued_at)
             VALUES (?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)`,
            [uuid(), licenseId, hashLicenseKey(key), key.slice(-4), encryptLicenseKey(key)],
          );
          adminLicense = { publicId, key, keyLast4: key.slice(-4), productCode: product.code, created: true };
        }
      }

      await audit({ organizationId:request.admin.organization_id, actorUserId:request.admin.id, action:'CUSTOMER_UPDATED', entityType:'customer', entityId:customer.id, ip:request.ip, metadata:{ name, email, discordId, status, accessLevel } });
      return { ok:true, customer:{ id:customer.id, name, email, discordId, discordUsername, status, accessLevel, notes }, adminLicense };
    } catch (e) {
      return reply.code(409).send({ ok:false, error:'CUSTOMER_UPDATE_FAILED', message:e.code === 'ER_DUP_ENTRY' ? 'Este Discord/e-mail já está vinculado a outro cadastro.' : e.message });
    }
  });

  app.patch('/api/v1/admin/licenses/:id', { preHandler: requireRole('root','owner','admin') }, async (request, reply) => {
    const b = request.body || {};
    const license = await one(
      `SELECT l.*, c.name AS customer_name, c.email, c.discord_id, c.id AS customer_id_ref
       FROM licenses l JOIN customers c ON c.id=l.customer_id
       WHERE l.id=? AND l.organization_id=? LIMIT 1`,
      [request.params.id, request.admin.organization_id],
    );
    if (!license) return reply.code(404).send({ ok:false, error:'NOT_FOUND' });

    const customerName = String(b.customerName ?? license.customer_name).trim();
    const email = String(b.email ?? license.email).trim().toLowerCase();
    const discordId = String(b.discordId ?? license.discord_id ?? '').trim() || null;
    const licenseType = String(b.licenseType ?? license.license_type).toLowerCase();
    let status = String(b.status ?? license.status).toLowerCase();
    const boundIp = normalizeIp(b.boundIp ?? license.bound_ip);
    const maxInstances = Math.max(1, Math.min(1000, Number(b.maxInstances ?? license.max_instances ?? 1)));
    const ipChangeLimit = Math.max(0, Math.min(10000, Number(b.ipChangeLimit ?? license.ip_change_limit ?? 0)));
    const notes = b.notes == null ? license.notes : (String(b.notes).trim() || null);

    if (!customerName || !email || !['permanent','temporary'].includes(licenseType) || !['active','suspended','revoked','expired'].includes(status) || !boundIp || net.isIP(boundIp) === 0) {
      return reply.code(400).send({ ok:false, error:'INVALID_INPUT' });
    }

    let expiresAt = null;
    if (licenseType === 'temporary') {
      const durationDays = Math.max(1, Math.min(3650, Number(b.durationDays || 30)));
      expiresAt = new Date(Date.now() + durationDays * 86400000);
      if (status === 'expired') status = 'active';
    } else if (status === 'expired') {
      status = 'active';
    }

    const conn = await db.getConnection();
    try {
      await conn.beginTransaction();
      await conn.execute('UPDATE customers SET name=?, email=?, discord_id=?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND organization_id=?',
        [customerName, email, discordId, license.customer_id_ref, request.admin.organization_id]);
      await conn.execute(
        `UPDATE licenses SET license_type=?, status=?, bound_ip=?, expires_at=?, max_instances=?, ip_change_limit=?, notes=?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND organization_id=?`,
        [licenseType, status, boundIp, expiresAt, maxInstances, ipChangeLimit, notes, license.id, request.admin.organization_id],
      );
      if (boundIp !== normalizeIp(license.bound_ip) || status !== 'active') {
        await conn.execute(`UPDATE license_sessions SET status='revoked', closed_at=CURRENT_TIMESTAMP WHERE license_id=? AND status='active'`, [license.id]);
        await conn.execute('UPDATE license_instances SET is_active=0 WHERE license_id=?', [license.id]);
      }
      await conn.commit();
    } catch (e) {
      await conn.rollback();
      return reply.code(409).send({ ok:false, error:'LICENSE_UPDATE_FAILED', message:e.code === 'ER_DUP_ENTRY' ? 'Os dados informados já estão em uso por outro cliente.' : e.message });
    } finally {
      conn.release();
    }

    await audit({ organizationId:request.admin.organization_id, actorUserId:request.admin.id, action:'LICENSE_UPDATED', entityType:'license', entityId:license.id, ip:request.ip, metadata:{ customerName, email, discordId, licenseType, status, boundIp, expiresAt, maxInstances, ipChangeLimit } });
    return { ok:true, license:{ id:license.id, licenseType, status, boundIp, expiresAt, maxInstances, ipChangeLimit } };
  });

  app.post('/api/v1/admin/system/reset', { preHandler: requireRole('root') }, async (request, reply) => {
    const phrase = String(request.body?.confirmation || '').trim().toUpperCase();
    const mode = request.body?.mode === 'factory' ? 'factory' : 'operation';
    if (phrase !== 'ZERAR TUDO') return reply.code(400).send({ ok:false, error:'CONFIRMATION_REQUIRED', message:'Digite exatamente ZERAR TUDO para confirmar.' });

    const org = request.admin.organization_id;
    const conn = await db.getConnection();
    const deleted = {};
    try {
      await conn.beginTransaction();
      const childDeletes = [
        ['discord_role_grants', `DELETE FROM discord_role_grants WHERE organization_id=?`],
        ['license_sessions', `DELETE s FROM license_sessions s JOIN licenses l ON l.id=s.license_id WHERE l.organization_id=?`],
        ['license_instances', `DELETE i FROM license_instances i JOIN licenses l ON l.id=i.license_id WHERE l.organization_id=?`],
        ['license_keys', `DELETE k FROM license_keys k JOIN licenses l ON l.id=k.license_id WHERE l.organization_id=?`],
        ['license_extensions', `DELETE e FROM license_extensions e JOIN licenses l ON l.id=e.license_id WHERE l.organization_id=?`],
        ['license_ip_history', `DELETE h FROM license_ip_history h JOIN licenses l ON l.id=h.license_id WHERE l.organization_id=?`],
      ];
      for (const [table, sql] of childDeletes) {
        const [result] = await conn.execute(sql, [org]);
        deleted[table] = Number(result.affectedRows || 0);
      }

      for (const table of ['ip_change_requests','license_requests','security_events','audit_logs','licenses','blocked_ips','blocked_discords','customers']) {
        const [result] = await conn.execute(`DELETE FROM ${table} WHERE organization_id=?`, [org]);
        deleted[table] = Number(result.affectedRows || 0);
      }

      if (mode === 'factory') {
        for (const table of ['api_keys','settings','products']) {
          const [result] = await conn.execute(`DELETE FROM ${table} WHERE organization_id=?`, [org]);
          deleted[table] = Number(result.affectedRows || 0);
        }
        await conn.execute(
          `INSERT INTO products (id, organization_id, code, name, description, current_version, discord_role_id, is_active)
           VALUES (?, ?, 'DK_BASE', 'DK Base', 'Produto padrão recriado após reset de fábrica', '1.0.0', ?, 1)`,
          [uuid(), org, config.discord.defaultProductRoleId || null],
        );
      }
      await conn.commit();
      request.log.warn({ organizationId:org, actorUserId:request.admin.id, mode, deleted }, '[DK ADMIN] Banco resetado pelo painel');
      return { ok:true, mode, deleted, message:mode === 'factory' ? 'Reset de fábrica concluído. O produto DK_BASE foi recriado.' : 'Dados operacionais zerados com sucesso.' };
    } catch (e) {
      await conn.rollback();
      request.log.error(e, '[DK ADMIN] Falha ao resetar banco');
      return reply.code(500).send({ ok:false, error:'RESET_FAILED', message:e.message });
    } finally {
      conn.release();
    }
  });

}
