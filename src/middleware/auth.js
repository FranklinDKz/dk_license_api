import { constantEqual, parseCookie, verifyAdminToken } from '../lib/security.js';
import { config } from '../lib/config.js';
import { one } from '../lib/db.js';

export async function requireAdmin(request, reply) {
  try {
    if (!['GET','HEAD','OPTIONS'].includes(request.method)) {
      const origin = request.headers.origin;
      if (origin && origin !== config.api.panelOrigin) return reply.code(403).send({ ok: false, error: 'INVALID_ORIGIN' });
    }
    const cookies = parseCookie(request.headers.cookie || '');
    const bearer = request.headers.authorization?.startsWith('Bearer ') ? request.headers.authorization.slice(7) : null;
    const token = cookies.dk_access || bearer;
    if (!token) throw new Error('Sem token');
    const payload = verifyAdminToken(token);
    const user = await one('SELECT id, organization_id, name, email, role, is_active FROM users WHERE id = ? LIMIT 1', [payload.sub]);
    if (!user || !user.is_active) throw new Error('Usuário inválido');
    request.admin = user;
  } catch {
    return reply.code(401).send({ ok: false, error: 'UNAUTHORIZED', message: 'Sessão administrativa inválida ou expirada.' });
  }
}

export async function requireService(request, reply) {
  const token = request.headers['x-service-token'] || '';
  if (!constantEqual(token, config.security.botServiceToken)) {
    return reply.code(401).send({ ok: false, error: 'INVALID_SERVICE_TOKEN' });
  }
}

export function requireRole(...roles) {
  return async (request, reply) => {
    await requireAdmin(request, reply);
    if (reply.sent) return;
    if (!roles.includes(request.admin.role)) {
      return reply.code(403).send({ ok: false, error: 'FORBIDDEN' });
    }
  };
}
