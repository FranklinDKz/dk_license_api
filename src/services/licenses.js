import net from 'node:net';
import { db, exec, many, one } from '../lib/db.js';
import { config } from '../lib/config.js';
import { encryptLicenseKey, generateLicenseKey, hashLicenseKey, hashSessionToken, normalizeIp, publicLicenseId, randomToken, uuid } from '../lib/security.js';
import { audit, securityEvent } from './audit.js';

function expiresAtFor(type, durationDays, durationMinutes) {
  if (type === 'permanent') return null;
  if (durationMinutes != null && Number.isFinite(Number(durationMinutes))) {
    const minutes = Math.max(1, Math.min(5256000, Number(durationMinutes)));
    return new Date(Date.now() + minutes * 60000);
  }
  const days = Math.max(1, Number(durationDays || 30));
  return new Date(Date.now() + days * 86400000);
}

function instanceStaleBefore() {
  const seconds = Math.max(60, Number(config.rules.sessionTtlSeconds || 180) + Number(config.rules.heartbeatGraceSeconds || 180));
  return new Date(Date.now() - seconds * 1000);
}

async function cleanupStaleLicenseRuntime(licenseId) {
  const staleBefore = instanceStaleBefore();
  await exec(`UPDATE license_sessions SET status='expired' WHERE license_id=? AND status='active' AND expires_at < ?`, [licenseId, new Date(Date.now() - Number(config.rules.heartbeatGraceSeconds || 0) * 1000)]);
  await exec(
    `UPDATE license_instances i
     LEFT JOIN license_sessions s ON s.license_id=i.license_id AND s.instance_uid=i.instance_uid AND s.status='active'
     SET i.is_active=0
     WHERE i.license_id=? AND i.is_active=1 AND s.id IS NULL`,
    [licenseId],
  );
  await exec(`UPDATE license_instances SET is_active=0 WHERE license_id=? AND is_active=1 AND last_seen_at < ?`, [licenseId, staleBefore]);
}

export async function getDefaultOrganization() {
  return one('SELECT id, name FROM organizations WHERE is_active = 1 ORDER BY created_at ASC LIMIT 1');
}

export async function getProductByCode(orgId, code) {
  return one('SELECT * FROM products WHERE organization_id = ? AND code = ? AND is_active = 1 LIMIT 1', [orgId, String(code || '').toUpperCase()]);
}

export async function createLicenseRequest({ organizationId, discordId, discordUsername, name, email, productCode, requestedIp, notes, actorIp, bypassRequestLimit = false }) {
  const product = await getProductByCode(organizationId, productCode);
  if (!product) return { ok: false, status: 404, error: 'PRODUCT_NOT_FOUND', message: 'Produto não encontrado.' };

  const ip = normalizeIp(requestedIp);
  if (!ip || net.isIP(ip) === 0) return { ok: false, status: 400, error: 'IP_REQUIRED', message: 'Informe o IP do servidor.' };

  const blockedIp = await one('SELECT id, reason FROM blocked_ips WHERE organization_id = ? AND ip_address = ? AND is_active = 1 LIMIT 1', [organizationId, ip]);
  if (blockedIp) {
    await securityEvent({ organizationId, eventType: 'BLOCKED_IP_REQUEST', severity: 'high', ip, discordId, details: { productCode } });
    return { ok: false, status: 403, error: 'IP_BLOCKED', message: 'Este IP está bloqueado.' };
  }
  const blockedDiscord = await one('SELECT id, reason FROM blocked_discords WHERE organization_id = ? AND discord_id = ? AND is_active = 1 LIMIT 1', [organizationId, discordId]);
  if (blockedDiscord) {
    await securityEvent({ organizationId, eventType: 'BLOCKED_DISCORD_REQUEST', severity: 'high', ip, discordId, details: { productCode } });
    return { ok: false, status: 403, error: 'DISCORD_BLOCKED', message: 'Esta conta Discord está bloqueada.' };
  }

  const count = await one(
    `SELECT COUNT(*) AS total FROM license_requests
     WHERE organization_id = ? AND requested_ip = ? AND product_id = ?`,
    [organizationId, ip, product.id],
  );
  if (!bypassRequestLimit && Number(count?.total || 0) >= config.rules.requestLimitPerIp) {
    await securityEvent({ organizationId, eventType: 'REQUEST_LIMIT_EXCEEDED', severity: 'high', ip, discordId, details: { productCode, limit: config.rules.requestLimitPerIp } });
    return { ok: false, status: 429, error: 'REQUEST_LIMIT_EXCEEDED', message: `Este IP já atingiu o limite de ${config.rules.requestLimitPerIp} solicitações.` };
  }

  let customer = await one('SELECT * FROM customers WHERE organization_id = ? AND discord_id = ? LIMIT 1', [organizationId, discordId]);
  if (!customer) {
    const customerId = uuid();
    await exec(
      `INSERT INTO customers (id, organization_id, name, email, discord_id, discord_username, status)
       VALUES (?, ?, ?, ?, ?, ?, 'active')`,
      [customerId, organizationId, name, String(email).toLowerCase(), discordId, discordUsername || null],
    );
    customer = { id: customerId };
  } else {
    await exec('UPDATE customers SET name = ?, email = ?, discord_username = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', [name, String(email).toLowerCase(), discordUsername || null, customer.id]);
  }

  const id = uuid();
  const requestCode = `REQ-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 999).toString().padStart(3, '0')}`;
  await exec(
    `INSERT INTO license_requests
     (id, organization_id, customer_id, product_id, request_code, requested_ip, requested_license_type, requested_duration_days, status, notes, discord_id)
     VALUES (?, ?, ?, ?, ?, ?, 'temporary', 30, 'pending', ?, ?)`,
    [id, organizationId, customer.id, product.id, requestCode, ip, notes || null, discordId],
  );
  await audit({ organizationId, actorDiscordId: discordId, action: 'LICENSE_REQUEST_CREATED', entityType: 'license_request', entityId: id, ip: actorIp || ip, metadata: { requestCode, product: product.code, requestedIp: ip } });
  return { ok: true, request: { id, requestCode, product: product.code, requestedIp: ip, status: 'pending' } };
}

export async function approveRequest({ requestId, expectedOrganizationId = null, actorUserId = null, actorDiscordId = null, licenseType = 'permanent', durationDays = null, durationMinutes = null, maxInstances = 1, ipChangeLimit = null, actorIp = null }) {
  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();
    const [rows] = await conn.execute(
      `SELECT lr.*, p.code AS product_code, p.name AS product_name, p.discord_role_id, c.name AS customer_name, c.email, c.discord_id AS customer_discord_id
       FROM license_requests lr
       JOIN products p ON p.id = lr.product_id
       JOIN customers c ON c.id = lr.customer_id
       WHERE lr.id = ? FOR UPDATE`,
      [requestId],
    );
    const request = rows[0];
    if (!request) throw Object.assign(new Error('Solicitação não encontrada.'), { code: 'NOT_FOUND' });
    if (expectedOrganizationId && request.organization_id !== expectedOrganizationId) throw Object.assign(new Error('Solicitação não encontrada.'), { code: 'NOT_FOUND' });
    if (request.status !== 'pending') throw Object.assign(new Error('Solicitação já processada.'), { code: 'ALREADY_PROCESSED' });

    let publicId;
    do {
      publicId = publicLicenseId();
      const [dupes] = await conn.execute('SELECT id FROM licenses WHERE public_id = ? LIMIT 1', [publicId]);
      if (!dupes[0]) break;
    } while (true);

    const licenseId = uuid();
    const plainKey = generateLicenseKey(request.product_code);
    const keyId = uuid();
    const keyHash = hashLicenseKey(plainKey);
    const expiresAt = expiresAtFor(licenseType, durationDays, durationMinutes);
    const changeLimit = ipChangeLimit == null ? config.rules.defaultIpChangeLimit : Math.max(0, Number(ipChangeLimit));

    await conn.execute(
      `INSERT INTO licenses
       (id, organization_id, customer_id, product_id, public_id, status, license_type, bound_ip, expires_at, max_instances, ip_change_limit, ip_changes_used, notes)
       VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, 0, ?)`,
      [licenseId, request.organization_id, request.customer_id, request.product_id, publicId, licenseType, request.requested_ip, expiresAt, Math.max(1, Number(maxInstances || 1)), changeLimit, request.notes],
    );
    await conn.execute(
      `INSERT INTO license_keys (id, license_id, key_hash, key_last4, key_ciphertext, is_active, issued_at)
       VALUES (?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)`,
      [keyId, licenseId, keyHash, plainKey.slice(-4), encryptLicenseKey(plainKey)],
    );
    if (request.discord_role_id && request.customer_discord_id) {
      await conn.execute(
        `INSERT INTO discord_role_grants
         (id, organization_id, product_id, license_id, discord_id, role_id, status, attempts)
         VALUES (?, ?, ?, ?, ?, ?, 'pending', 0)
         ON DUPLICATE KEY UPDATE discord_id=VALUES(discord_id), status=IF(status='granted','granted','pending'), last_error=NULL, updated_at=CURRENT_TIMESTAMP`,
        [uuid(), request.organization_id, request.product_id, licenseId, String(request.customer_discord_id), String(request.discord_role_id)],
      );
    }
    await conn.execute(
      `INSERT INTO license_ip_history (id, license_id, old_ip, new_ip, reason, changed_by_user_id, changed_by_discord_id)
       VALUES (?, ?, NULL, ?, 'initial_activation', ?, ?)`,
      [uuid(), licenseId, request.requested_ip, actorUserId, actorDiscordId],
    );
    await conn.execute(
      `UPDATE license_requests SET status = 'approved', reviewed_at = CURRENT_TIMESTAMP, reviewed_by_user_id = ?, issued_license_id = ? WHERE id = ?`,
      [actorUserId, licenseId, request.id],
    );
    await conn.commit();

    await audit({ organizationId: request.organization_id, actorUserId, actorDiscordId, action: 'LICENSE_APPROVED', entityType: 'license', entityId: licenseId, ip: actorIp, metadata: { publicId, requestId, licenseType, durationDays, durationMinutes, expiresAt, boundIp: request.requested_ip } });
    return {
      ok: true,
      license: {
        id: licenseId,
        publicId,
        key: plainKey,
        keyLast4: plainKey.slice(-4),
        productCode: request.product_code,
        productName: request.product_name,
        customerName: request.customer_name,
        customerDiscordId: request.customer_discord_id,
        boundIp: request.requested_ip,
        licenseType,
        expiresAt,
        maxInstances: Math.max(1, Number(maxInstances || 1)),
        ipChangeLimit: changeLimit,
        discordRoleId: request.discord_role_id || null,
      },
    };
  } catch (error) {
    await conn.rollback();
    return { ok: false, status: error.code === 'NOT_FOUND' ? 404 : 409, error: error.code || 'APPROVAL_FAILED', message: error.message };
  } finally {
    conn.release();
  }
}

export async function rejectRequest({ requestId, expectedOrganizationId = null, actorUserId = null, actorDiscordId = null, reason = 'Recusado pelo administrador', actorIp = null }) {
  const request = await one('SELECT * FROM license_requests WHERE id = ? LIMIT 1', [requestId]);
  if (!request || (expectedOrganizationId && request.organization_id !== expectedOrganizationId)) return { ok: false, status: 404, error: 'NOT_FOUND' };
  if (request.status !== 'pending') return { ok: false, status: 409, error: 'ALREADY_PROCESSED' };
  await exec(`UPDATE license_requests SET status = 'rejected', rejection_reason = ?, reviewed_at = CURRENT_TIMESTAMP, reviewed_by_user_id = ? WHERE id = ?`, [reason, actorUserId, requestId]);
  await audit({ organizationId: request.organization_id, actorUserId, actorDiscordId, action: 'LICENSE_REQUEST_REJECTED', entityType: 'license_request', entityId: requestId, ip: actorIp, metadata: { reason } });
  return { ok: true };
}

export async function activateFiveM({ key, productCode, instanceId, ip }) {
  const keyHash = hashLicenseKey(key || '');
  const license = await one(
    `SELECT l.*, p.code AS product_code, p.name AS product_name, lk.id AS key_id,
            c.access_level AS customer_access_level
     FROM license_keys lk
     JOIN licenses l ON l.id = lk.license_id
     JOIN products p ON p.id = l.product_id
     JOIN customers c ON c.id = l.customer_id
     WHERE lk.key_hash = ? AND lk.is_active = 1 LIMIT 1`,
    [keyHash],
  );
  const requestIp = normalizeIp(ip);
  if (!license) {
    await securityEvent({ eventType: 'INVALID_LICENSE_KEY', severity: 'high', ip: requestIp, details: { productCode } });
    return { ok: false, status: 401, error: 'INVALID_LICENSE' };
  }
  const adminBypass = license.customer_access_level === 'admin';
  if (!adminBypass && license.status !== 'active') return { ok: false, status: 403, error: `LICENSE_${license.status.toUpperCase()}` };
  if (!adminBypass && license.expires_at && new Date(license.expires_at).getTime() <= Date.now()) {
    await exec(`UPDATE licenses SET status = 'expired' WHERE id = ?`, [license.id]);
    return { ok: false, status: 403, error: 'LICENSE_EXPIRED' };
  }
  if (license.product_code !== String(productCode || '').toUpperCase()) {
    await securityEvent({ organizationId: license.organization_id, licenseId: license.id, eventType: 'PRODUCT_MISMATCH', severity: 'high', ip: requestIp, details: { expected: license.product_code, received: productCode } });
    return { ok: false, status: 403, error: 'PRODUCT_MISMATCH' };
  }
  if (!adminBypass && normalizeIp(license.bound_ip) !== requestIp) {
    await securityEvent({ organizationId: license.organization_id, licenseId: license.id, eventType: 'IP_MISMATCH', severity: 'high', ip: requestIp, details: { expected: license.bound_ip, received: requestIp, instanceId } });
    return { ok: false, status: 403, error: 'IP_MISMATCH' };
  }
  if (!instanceId || String(instanceId).length < 8) return { ok: false, status: 400, error: 'INVALID_INSTANCE_ID' };

  // Limpa sessões/instâncias abandonadas automaticamente para não exigir reset manual.
  await cleanupStaleLicenseRuntime(license.id);

  const existing = await one('SELECT id FROM license_instances WHERE license_id = ? AND instance_uid = ? LIMIT 1', [license.id, instanceId]);
  if (!existing) {
    const activeCount = await one('SELECT COUNT(*) AS total FROM license_instances WHERE license_id = ? AND is_active = 1', [license.id]);
    if (!adminBypass && Number(activeCount?.total || 0) >= Number(license.max_instances || 1)) {
      await securityEvent({ organizationId: license.organization_id, licenseId: license.id, eventType: 'INSTANCE_LIMIT_EXCEEDED', severity: 'high', ip: requestIp, details: { instanceId, maxInstances: license.max_instances } });
      return { ok: false, status: 409, error: 'INSTANCE_LIMIT_EXCEEDED' };
    }
    await exec(
      `INSERT INTO license_instances (id, license_id, instance_uid, first_ip, last_ip, is_active, last_seen_at)
       VALUES (?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)`,
      [uuid(), license.id, instanceId, requestIp, requestIp],
    );
  } else {
    await exec('UPDATE license_instances SET last_ip = ?, is_active = 1, last_seen_at = CURRENT_TIMESTAMP WHERE id = ?', [requestIp, existing.id]);
  }

  await exec('UPDATE license_sessions SET status = \'replaced\' WHERE license_id = ? AND instance_uid = ? AND status = \'active\'', [license.id, instanceId]);
  const sessionToken = randomToken(36);
  const tokenHash = hashSessionToken(sessionToken);
  const expiresAt = new Date(Date.now() + config.rules.sessionTtlSeconds * 1000);
  const sessionId = uuid();
  await exec(
    `INSERT INTO license_sessions (id, license_id, instance_uid, token_hash, ip_address, status, expires_at, last_heartbeat_at)
     VALUES (?, ?, ?, ?, ?, 'active', ?, CURRENT_TIMESTAMP)`,
    [sessionId, license.id, instanceId, tokenHash, requestIp, expiresAt],
  );
  await exec('UPDATE licenses SET last_auth_at = CURRENT_TIMESTAMP, last_ip = ? WHERE id = ?', [requestIp, license.id]);
  await audit({ organizationId: license.organization_id, action: 'FIVEM_ACTIVATED', entityType: 'license', entityId: license.id, ip: requestIp, metadata: { instanceId, sessionId } });

  return {
    ok: true,
    sessionToken,
    sessionTtlSeconds: config.rules.sessionTtlSeconds,
    license: {
      publicId: license.public_id,
      productCode: license.product_code,
      productName: license.product_name,
      type: license.license_type,
      expiresAt: license.expires_at,
      boundIp: license.bound_ip,
      maxInstances: license.max_instances,
      adminBypass,
    },
  };
}

export async function heartbeatFiveM({ sessionToken, instanceId, ip }) {
  const tokenHash = hashSessionToken(sessionToken || '');
  const requestIp = normalizeIp(ip);
  const session = await one(
    `SELECT s.id, s.license_id, s.instance_uid, s.ip_address, s.status, s.expires_at AS session_expires_at,
            l.organization_id, l.status AS license_status, l.expires_at AS license_expires_at, l.bound_ip, l.public_id, p.code AS product_code,
            c.access_level AS customer_access_level
     FROM license_sessions s
     JOIN licenses l ON l.id = s.license_id
     JOIN products p ON p.id = l.product_id
     JOIN customers c ON c.id = l.customer_id
     WHERE s.token_hash = ? AND s.status = 'active' LIMIT 1`,
    [tokenHash],
  );
  if (!session) return { ok: false, status: 401, error: 'INVALID_SESSION' };
  const sessionExpiryMs = new Date(session.session_expires_at).getTime();
  const heartbeatGraceMs = Math.max(0, Number(config.rules.heartbeatGraceSeconds || 0)) * 1000;
  if (sessionExpiryMs + heartbeatGraceMs <= Date.now()) {
    await exec(`UPDATE license_sessions SET status = 'expired' WHERE id = ?`, [session.id]);
    await exec(`UPDATE license_instances SET is_active=0 WHERE license_id=? AND instance_uid=?`, [session.license_id, session.instance_uid]);
    return { ok: false, status: 401, error: 'SESSION_EXPIRED' };
  }
  const adminBypass = session.customer_access_level === 'admin';
  if (session.instance_uid !== instanceId) return { ok: false, status: 403, error: 'INSTANCE_MISMATCH' };
  if (!adminBypass && (normalizeIp(session.ip_address) !== requestIp || normalizeIp(session.bound_ip) !== requestIp)) {
    await securityEvent({ organizationId: session.organization_id, licenseId: session.license_id, eventType: 'HEARTBEAT_IP_MISMATCH', severity: 'critical', ip: requestIp, details: { instanceId } });
    await exec(`UPDATE license_sessions SET status = 'revoked' WHERE id = ?`, [session.id]);
    return { ok: false, status: 403, error: 'IP_MISMATCH' };
  }
  if (!adminBypass && session.license_status !== 'active') return { ok: false, status: 403, error: `LICENSE_${String(session.license_status).toUpperCase()}` };
  if (!adminBypass && session.license_expires_at && new Date(session.license_expires_at).getTime() <= Date.now()) {
    await exec(`UPDATE licenses SET status = 'expired' WHERE id = ?`, [session.license_id]);
    await exec(`UPDATE license_sessions SET status = 'expired' WHERE id = ?`, [session.id]);
    return { ok: false, status: 403, error: 'LICENSE_EXPIRED' };
  }

  const newExpiry = new Date(Date.now() + config.rules.sessionTtlSeconds * 1000);
  // Mantém o mesmo token durante a sessão. Isso evita INVALID_SESSION por heartbeats sobrepostos
  // ou por resposta perdida após uma rotação de token. A validade continua sendo renovada pelo TTL.
  await exec('UPDATE license_sessions SET expires_at = ?, last_heartbeat_at = CURRENT_TIMESTAMP WHERE id = ?', [newExpiry, session.id]);
  await exec('UPDATE license_instances SET is_active=1, last_seen_at = CURRENT_TIMESTAMP, last_ip = ? WHERE license_id = ? AND instance_uid = ?', [requestIp, session.license_id, instanceId]);
  await exec('UPDATE licenses SET last_heartbeat_at = CURRENT_TIMESTAMP WHERE id = ?', [session.license_id]);
  return { ok: true, status: 'valid', sessionToken, sessionTtlSeconds: config.rules.sessionTtlSeconds, licensePublicId: session.public_id, adminBypass };
}

export async function deactivateFiveM({ sessionToken, instanceId, ip }) {
  const tokenHash = hashSessionToken(sessionToken || '');
  const session = await one('SELECT * FROM license_sessions WHERE token_hash = ? AND instance_uid = ? LIMIT 1', [tokenHash, instanceId]);
  if (!session) return { ok: false, status: 404, error: 'SESSION_NOT_FOUND' };
  await exec(`UPDATE license_sessions SET status = 'closed', closed_at = CURRENT_TIMESTAMP WHERE id = ?`, [session.id]);
  await exec(`UPDATE license_instances SET is_active=0, last_seen_at=CURRENT_TIMESTAMP WHERE license_id=? AND instance_uid=?`, [session.license_id, session.instance_uid]);
  await audit({ action: 'FIVEM_DEACTIVATED', entityType: 'license', entityId: session.license_id, ip: normalizeIp(ip), metadata: { instanceId } });
  return { ok: true };
}

export async function requestIpChange({ organizationId, discordId, licensePublicId, newIp }) {
  const license = await one(
    `SELECT l.*, c.discord_id, p.code AS product_code FROM licenses l JOIN customers c ON c.id = l.customer_id JOIN products p ON p.id = l.product_id
     WHERE l.organization_id = ? AND l.public_id = ? LIMIT 1`,
    [organizationId, licensePublicId],
  );
  if (!license || license.discord_id !== discordId) return { ok: false, status: 404, error: 'LICENSE_NOT_FOUND' };
  if (license.ip_changes_used >= license.ip_change_limit) return { ok: false, status: 403, error: 'IP_CHANGE_LIMIT_REACHED' };
  const normalized = normalizeIp(newIp);
  if (!normalized || net.isIP(normalized) === 0) return { ok: false, status: 400, error: 'INVALID_IP' };
  const existing = await one(`SELECT id FROM ip_change_requests WHERE license_id = ? AND status = 'pending' LIMIT 1`, [license.id]);
  if (existing) return { ok: false, status: 409, error: 'PENDING_IP_CHANGE_EXISTS' };
  const id = uuid();
  await exec(
    `INSERT INTO ip_change_requests (id, organization_id, license_id, requested_by_discord_id, old_ip, new_ip, status)
     VALUES (?, ?, ?, ?, ?, ?, 'pending')`,
    [id, organizationId, license.id, discordId, license.bound_ip, normalized],
  );
  await audit({ organizationId, actorDiscordId: discordId, action: 'IP_CHANGE_REQUESTED', entityType: 'license', entityId: license.id, ip: normalized, metadata: { oldIp: license.bound_ip, newIp: normalized } });
  return { ok: true, requestId: id };
}

export async function approveIpChange({ requestId, expectedOrganizationId = null, actorUserId = null, actorDiscordId = null, actorIp = null }) {
  const change = await one(`SELECT r.*, l.ip_changes_used, l.ip_change_limit FROM ip_change_requests r JOIN licenses l ON l.id = r.license_id WHERE r.id = ? LIMIT 1`, [requestId]);
  if (!change || (expectedOrganizationId && change.organization_id !== expectedOrganizationId)) return { ok: false, status: 404, error: 'NOT_FOUND' };
  if (change.status !== 'pending') return { ok: false, status: 409, error: 'ALREADY_PROCESSED' };
  if (change.ip_changes_used >= change.ip_change_limit) return { ok: false, status: 403, error: 'IP_CHANGE_LIMIT_REACHED' };
  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();
    await conn.execute('UPDATE licenses SET bound_ip = ?, ip_changes_used = ip_changes_used + 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?', [change.new_ip, change.license_id]);
    await conn.execute(`UPDATE license_sessions SET status = 'revoked' WHERE license_id = ? AND status = 'active'`, [change.license_id]);
    await conn.execute(`UPDATE license_instances SET is_active = 0 WHERE license_id = ?`, [change.license_id]);
    await conn.execute(`UPDATE ip_change_requests SET status = 'approved', reviewed_at = CURRENT_TIMESTAMP, reviewed_by_user_id = ? WHERE id = ?`, [actorUserId, requestId]);
    await conn.execute(
      `INSERT INTO license_ip_history (id, license_id, old_ip, new_ip, reason, changed_by_user_id, changed_by_discord_id)
       VALUES (?, ?, ?, ?, 'approved_ip_change', ?, ?)`,
      [uuid(), change.license_id, change.old_ip, change.new_ip, actorUserId, actorDiscordId],
    );
    await conn.commit();
    await audit({ organizationId: change.organization_id, actorUserId, actorDiscordId, action: 'IP_CHANGE_APPROVED', entityType: 'license', entityId: change.license_id, ip: actorIp, metadata: { oldIp: change.old_ip, newIp: change.new_ip } });
    return { ok: true };
  } catch (e) {
    await conn.rollback();
    return { ok: false, status: 500, error: 'IP_CHANGE_FAILED', message: e.message };
  } finally { conn.release(); }
}

export async function changeLicenseStatus({ licenseId, organizationId = null, status, actorUserId, actorIp }) {
  const allowed = ['active', 'suspended', 'revoked'];
  if (!allowed.includes(status)) return { ok: false, status: 400, error: 'INVALID_STATUS' };
  const license = organizationId ? await one('SELECT * FROM licenses WHERE id = ? AND organization_id = ? LIMIT 1', [licenseId, organizationId]) : await one('SELECT * FROM licenses WHERE id = ? LIMIT 1', [licenseId]);
  if (!license) return { ok: false, status: 404, error: 'NOT_FOUND' };
  await exec('UPDATE licenses SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', [status, licenseId]);
  if (status !== 'active') await exec(`UPDATE license_sessions SET status = 'revoked' WHERE license_id = ? AND status = 'active'`, [licenseId]);
  await audit({ organizationId: license.organization_id, actorUserId, action: `LICENSE_${status.toUpperCase()}`, entityType: 'license', entityId: licenseId, ip: actorIp });
  return { ok: true };
}

export async function extendLicense({ licenseId, organizationId = null, days, minutes, permanent, actorUserId, actorIp }) {
  const license = organizationId ? await one('SELECT * FROM licenses WHERE id = ? AND organization_id = ? LIMIT 1', [licenseId, organizationId]) : await one('SELECT * FROM licenses WHERE id = ? LIMIT 1', [licenseId]);
  if (!license) return { ok: false, status: 404, error: 'NOT_FOUND' };
  let addedMinutes = 0;
  if (permanent) {
    await exec(`UPDATE licenses SET license_type = 'permanent', expires_at = NULL, status = IF(status='expired','active',status), updated_at=CURRENT_TIMESTAMP WHERE id = ?`, [licenseId]);
  } else {
    addedMinutes = minutes != null ? Math.max(1, Math.min(5256000, Number(minutes))) : Math.max(1, Number(days || 30)) * 1440;
    const now = Date.now();
    const currentExpiry = license.expires_at ? new Date(license.expires_at).getTime() : 0;
    const base = currentExpiry > now ? currentExpiry : now;
    const newExpiry = new Date(base + addedMinutes * 60000);
    await exec(
      `UPDATE licenses SET license_type = 'temporary', expires_at = ?, status = IF(status='expired','active',status), updated_at=CURRENT_TIMESTAMP WHERE id = ?`,
      [newExpiry, licenseId],
    );
  }
  const daysAdded = permanent ? 0 : Math.floor(addedMinutes / 1440);
  await exec(`INSERT INTO license_extensions (id, license_id, days_added, made_permanent, changed_by_user_id) VALUES (?, ?, ?, ?, ?)`, [uuid(), licenseId, daysAdded, permanent ? 1 : 0, actorUserId]);
  await audit({ organizationId: license.organization_id, actorUserId, action: 'LICENSE_EXTENDED', entityType: 'license', entityId: licenseId, ip: actorIp, metadata: { days, minutes: addedMinutes, permanent: !!permanent } });
  return { ok: true };
}

export async function regenerateKey({ licenseId, organizationId = null, actorUserId, actorIp }) {
  const license = organizationId ? await one(`SELECT l.*, p.code AS product_code FROM licenses l JOIN products p ON p.id = l.product_id WHERE l.id = ? AND l.organization_id = ? LIMIT 1`, [licenseId, organizationId]) : await one(`SELECT l.*, p.code AS product_code FROM licenses l JOIN products p ON p.id = l.product_id WHERE l.id = ? LIMIT 1`, [licenseId]);
  if (!license) return { ok: false, status: 404, error: 'NOT_FOUND' };
  const key = generateLicenseKey(license.product_code);
  await exec('UPDATE license_keys SET is_active = 0, revoked_at = CURRENT_TIMESTAMP WHERE license_id = ? AND is_active = 1', [licenseId]);
  await exec(`INSERT INTO license_keys (id, license_id, key_hash, key_last4, key_ciphertext, is_active, issued_at) VALUES (?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)`, [uuid(), licenseId, hashLicenseKey(key), key.slice(-4), encryptLicenseKey(key)]);
  await exec(`UPDATE license_sessions SET status = 'revoked' WHERE license_id = ? AND status = 'active'`, [licenseId]);
  await audit({ organizationId: license.organization_id, actorUserId, action: 'LICENSE_KEY_REGENERATED', entityType: 'license', entityId: licenseId, ip: actorIp, metadata: { keyLast4: key.slice(-4) } });
  return { ok: true, key, keyLast4: key.slice(-4), publicId: license.public_id };
}

export async function listDiscordLicenses(organizationId, discordId) {
  return many(
    `SELECT l.public_id, l.status, l.license_type, l.bound_ip, l.expires_at, l.ip_change_limit, l.ip_changes_used, p.code AS product_code, p.name AS product_name, lk.key_last4
     FROM licenses l JOIN customers c ON c.id = l.customer_id JOIN products p ON p.id = l.product_id
     LEFT JOIN license_keys lk ON lk.license_id = l.id AND lk.is_active = 1
     WHERE l.organization_id = ? AND c.discord_id = ? ORDER BY l.created_at DESC`,
    [organizationId, discordId],
  );
}


export async function forceLicenseIp({ licenseId, organizationId, newIp, actorUserId, actorIp }) {
  const normalized = normalizeIp(newIp);
  if (!normalized || net.isIP(normalized) === 0) return { ok: false, status: 400, error: 'INVALID_IP' };
  const license = await one('SELECT * FROM licenses WHERE id=? AND organization_id=? LIMIT 1', [licenseId, organizationId]);
  if (!license) return { ok: false, status: 404, error: 'NOT_FOUND' };
  await exec('UPDATE licenses SET bound_ip=?, updated_at=CURRENT_TIMESTAMP WHERE id=?', [normalized, licenseId]);
  await exec(`UPDATE license_sessions SET status='revoked' WHERE license_id=? AND status='active'`, [licenseId]);
  await exec('UPDATE license_instances SET is_active=0 WHERE license_id=?', [licenseId]);
  await exec(`INSERT INTO license_ip_history (id, license_id, old_ip, new_ip, reason, changed_by_user_id) VALUES (?, ?, ?, ?, 'admin_force_change', ?)`, [uuid(), licenseId, license.bound_ip, normalized, actorUserId]);
  await audit({ organizationId, actorUserId, action:'LICENSE_IP_FORCED', entityType:'license', entityId:licenseId, ip:actorIp, metadata:{ oldIp:license.bound_ip, newIp:normalized } });
  return { ok:true };
}

export async function updateLicenseLimits({ licenseId, organizationId, maxInstances, ipChangeLimit, actorUserId, actorIp }) {
  const license = await one('SELECT * FROM licenses WHERE id=? AND organization_id=? LIMIT 1', [licenseId, organizationId]);
  if (!license) return { ok:false, status:404, error:'NOT_FOUND' };
  const instances = Math.max(1, Math.min(100, Number(maxInstances || 1)));
  const changes = Math.max(0, Math.min(1000, Number(ipChangeLimit ?? license.ip_change_limit)));
  await exec('UPDATE licenses SET max_instances=?, ip_change_limit=?, updated_at=CURRENT_TIMESTAMP WHERE id=?', [instances, changes, licenseId]);
  await audit({ organizationId, actorUserId, action:'LICENSE_LIMITS_UPDATED', entityType:'license', entityId:licenseId, ip:actorIp, metadata:{ maxInstances:instances, ipChangeLimit:changes } });
  return { ok:true };
}

export async function resetLicenseInstances({ licenseId, organizationId, actorUserId, actorIp }) {
  const license = await one('SELECT id FROM licenses WHERE id=? AND organization_id=? LIMIT 1', [licenseId, organizationId]);
  if (!license) return { ok:false, status:404, error:'NOT_FOUND' };
  await exec(`UPDATE license_sessions SET status='revoked' WHERE license_id=? AND status='active'`, [licenseId]);
  await exec('DELETE FROM license_instances WHERE license_id=?', [licenseId]);
  await audit({ organizationId, actorUserId, action:'LICENSE_INSTANCES_RESET', entityType:'license', entityId:licenseId, ip:actorIp });
  return { ok:true };
}
