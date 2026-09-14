import { exec } from '../lib/db.js';
import { uuid } from '../lib/security.js';

export async function audit({ organizationId = null, actorUserId = null, actorDiscordId = null, action, entityType = null, entityId = null, ip = null, metadata = {} }) {
  await exec(
    `INSERT INTO audit_logs (id, organization_id, actor_user_id, actor_discord_id, action, entity_type, entity_id, ip_address, metadata_json)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [uuid(), organizationId, actorUserId, actorDiscordId, action, entityType, entityId, ip, JSON.stringify(metadata || {})],
  );
}

export async function securityEvent({ organizationId = null, licenseId = null, eventType, severity = 'medium', ip = null, discordId = null, details = {} }) {
  await exec(
    `INSERT INTO security_events (id, organization_id, license_id, event_type, severity, ip_address, discord_id, details_json)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [uuid(), organizationId, licenseId, eventType, severity, ip, discordId, JSON.stringify(details || {})],
  );
}
