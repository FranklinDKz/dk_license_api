import { requireService } from '../middleware/auth.js';
import { getDefaultOrganization, createLicenseRequest, approveRequest, rejectRequest, listDiscordLicenses, requestIpChange, approveIpChange } from '../services/licenses.js';
import { exec, many, one } from '../lib/db.js';

export async function serviceRoutes(app) {
  app.addHook('preHandler', async (request, reply) => {
    if (request.url.startsWith('/api/v1/service/')) await requireService(request, reply);
  });

  app.get('/api/v1/service/products', async (_request, reply) => {
    const org = await getDefaultOrganization();
    if (!org) return reply.code(404).send({ ok: false, error: 'NO_ORGANIZATION' });
    const products = await many('SELECT code, name, description FROM products WHERE organization_id = ? AND is_active = 1 ORDER BY name', [org.id]);
    return { ok: true, products };
  });

  app.post('/api/v1/service/license-requests', async (request, reply) => {
    const org = await getDefaultOrganization();
    const b = request.body || {};
    if (!org || !b.discordId || !b.name || !b.email || !b.productCode || !b.requestedIp) return reply.code(400).send({ ok: false, error: 'INVALID_INPUT' });
    const result = await createLicenseRequest({ organizationId: org.id, discordId: String(b.discordId), discordUsername: b.discordUsername, name: b.name, email: b.email, productCode: b.productCode, requestedIp: b.requestedIp, notes: b.notes, actorIp: request.ip });
    return result.ok ? result : reply.code(result.status || 400).send(result);
  });

  app.get('/api/v1/service/licenses/:discordId', async (request, reply) => {
    const org = await getDefaultOrganization();
    if (!org) return reply.code(404).send({ ok: false, error: 'NO_ORGANIZATION' });
    const licenses = await listDiscordLicenses(org.id, String(request.params.discordId));
    return { ok: true, licenses };
  });

  app.post('/api/v1/service/ip-change-requests', async (request, reply) => {
    const org = await getDefaultOrganization();
    const b = request.body || {};
    if (!org) return reply.code(404).send({ ok:false, error:'NO_ORGANIZATION' });
    const result = await requestIpChange({ organizationId: org.id, discordId: String(b.discordId || ''), licensePublicId: String(b.licensePublicId || ''), newIp: b.newIp });
    return result.ok ? result : reply.code(result.status || 400).send(result);
  });

  app.get('/api/v1/service/pending', async () => {
    const org = await getDefaultOrganization();
    const requests = org ? await many(
      `SELECT lr.id, lr.request_code, lr.requested_ip, lr.created_at, c.name AS customer_name, c.email, c.discord_id, p.code AS product_code, p.name AS product_name
       FROM license_requests lr JOIN customers c ON c.id=lr.customer_id JOIN products p ON p.id=lr.product_id
       WHERE lr.organization_id=? AND lr.status='pending' ORDER BY lr.created_at ASC LIMIT 100`, [org.id]) : [];
    const ipChanges = org ? await many(
      `SELECT r.id, l.public_id, r.old_ip, r.new_ip, r.requested_by_discord_id, r.created_at
       FROM ip_change_requests r JOIN licenses l ON l.id=r.license_id
       WHERE r.organization_id=? AND r.status='pending' ORDER BY r.created_at ASC LIMIT 100`, [org.id]) : [];
    return { ok: true, requests, ipChanges };
  });

  app.post('/api/v1/service/requests/:id/approve', async (request, reply) => {
    const b = request.body || {};
    const org = await getDefaultOrganization();
    const result = await approveRequest({ requestId: request.params.id, expectedOrganizationId: org?.id || null, actorDiscordId: String(b.actorDiscordId || ''), licenseType: b.licenseType || 'permanent', durationDays: b.durationDays, maxInstances: b.maxInstances || 1, ipChangeLimit: b.ipChangeLimit, actorIp: request.ip });
    return result.ok ? result : reply.code(result.status || 400).send(result);
  });

  app.post('/api/v1/service/requests/:id/reject', async (request, reply) => {
    const b = request.body || {};
    const org = await getDefaultOrganization();
    const result = await rejectRequest({ requestId: request.params.id, expectedOrganizationId: org?.id || null, actorDiscordId: String(b.actorDiscordId || ''), reason: b.reason, actorIp: request.ip });
    return result.ok ? result : reply.code(result.status || 400).send(result);
  });

  app.post('/api/v1/service/ip-change/:id/approve', async (request, reply) => {
    const b = request.body || {};
    const org = await getDefaultOrganization();
    const result = await approveIpChange({ requestId: request.params.id, expectedOrganizationId: org?.id || null, actorDiscordId: String(b.actorDiscordId || ''), actorIp: request.ip });
    return result.ok ? result : reply.code(result.status || 400).send(result);
  });


  app.get('/api/v1/service/role-grants', async (request, reply) => {
    const org = await getDefaultOrganization();
    if (!org) return reply.code(404).send({ ok:false, error:'NO_ORGANIZATION' });
    const requestedLimit = Number.parseInt(String(request.query?.limit || '25'), 10);
    const limit = Number.isFinite(requestedLimit) ? Math.max(1, Math.min(100, requestedLimit)) : 25;
    const grants = await many(
      `SELECT g.id, g.discord_id AS discordId, g.role_id AS roleId, g.status, g.attempts,
              l.public_id AS licensePublicId, p.code AS productCode, p.name AS productName
       FROM discord_role_grants g
       JOIN licenses l ON l.id=g.license_id
       JOIN products p ON p.id=g.product_id
       WHERE g.organization_id=?
         AND g.status IN ('pending','failed')
         AND g.attempts < 20
         AND (g.status='pending' OR g.updated_at < DATE_SUB(NOW(), INTERVAL 30 SECOND))
       ORDER BY g.created_at ASC
       LIMIT ${limit}`,
      [org.id],
    );
    return { ok:true, grants };
  });

  app.post('/api/v1/service/role-grants/:id/result', async (request, reply) => {
    const org = await getDefaultOrganization();
    if (!org) return reply.code(404).send({ ok:false, error:'NO_ORGANIZATION' });
    const grant = await one('SELECT * FROM discord_role_grants WHERE id=? AND organization_id=? LIMIT 1', [request.params.id, org.id]);
    if (!grant) return reply.code(404).send({ ok:false, error:'NOT_FOUND' });
    const success = !!request.body?.success;
    const error = String(request.body?.error || '').slice(0, 2000) || null;
    if (success) {
      await exec(`UPDATE discord_role_grants SET status='granted', attempts=attempts+1, last_error=NULL, granted_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE id=?`, [grant.id]);
    } else {
      await exec(`UPDATE discord_role_grants SET status='failed', attempts=attempts+1, last_error=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`, [error, grant.id]);
    }
    return { ok:true };
  });
}
