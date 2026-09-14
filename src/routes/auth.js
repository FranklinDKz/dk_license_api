import bcrypt from 'bcryptjs';
import { config } from '../lib/config.js';
import { exec, one } from '../lib/db.js';
import { rateLimit } from '../lib/rate-limit.js';
import { signAdminToken } from '../lib/security.js';
import { audit } from '../services/audit.js';
import { requireAdmin } from '../middleware/auth.js';

function issueAdminSession(reply, user) {
  const token = signAdminToken(user);
  const secure = config.api.cookieSecure ? '; Secure' : '';
  const sameSite = config.api.cookieSameSite;
  const maxAge = config.security.adminSessionHours * 3600;
  reply.header('Set-Cookie', `dk_access=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=${sameSite}; Max-Age=${maxAge}${secure}`);
  return { token, expiresInSeconds: maxAge };
}

export async function authRoutes(app) {
  app.post('/api/v1/auth/login', async (request, reply) => {
    const rl = rateLimit({ windowMs: 15 * 60_000, limit: config.security.loginLimit, key: `login:${request.ip}` });
    if (!rl.allowed) return reply.code(429).send({ ok: false, error: 'RATE_LIMIT', retryAfterMs: rl.retryAfterMs });
    const { email, password } = request.body || {};
    if (!email || !password) return reply.code(400).send({ ok: false, error: 'INVALID_INPUT' });
    const user = await one('SELECT * FROM users WHERE email = ? AND is_active = 1 LIMIT 1', [String(email).trim().toLowerCase()]);
    if (!user || !(await bcrypt.compare(String(password), user.password_hash))) {
      await audit({ organizationId: user?.organization_id || null, actorUserId: user?.id || null, action: 'ADMIN_LOGIN_FAILED', ip: request.ip, metadata: { email: String(email).toLowerCase() } });
      return reply.code(401).send({ ok: false, error: 'INVALID_CREDENTIALS', message: 'E-mail ou senha inválidos.' });
    }
    await exec('UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);
    const session = issueAdminSession(reply, user);
    await audit({ organizationId: user.organization_id, actorUserId: user.id, action: 'ADMIN_LOGIN_SUCCESS', ip: request.ip });
    return { ok: true, accessToken: session.token, expiresInSeconds: session.expiresInSeconds, user: { id: user.id, name: user.name, email: user.email, role: user.role } };
  });

  app.post('/api/v1/auth/logout', { preHandler: requireAdmin }, async (request, reply) => {
    const secure = config.api.cookieSecure ? '; Secure' : '';
    const sameSite = config.api.cookieSameSite;
    reply.header('Set-Cookie', `dk_access=; Path=/; HttpOnly; SameSite=${sameSite}; Max-Age=0${secure}`);
    return { ok: true };
  });

  app.post('/api/v1/auth/refresh', { preHandler: requireAdmin }, async (request, reply) => {
    const session = issueAdminSession(reply, request.admin);
    return { ok: true, accessToken: session.token, expiresInSeconds: session.expiresInSeconds, user: request.admin };
  });

  app.get('/api/v1/auth/me', { preHandler: requireAdmin }, async (request, reply) => {
    const session = issueAdminSession(reply, request.admin);
    return { ok: true, accessToken: session.token, expiresInSeconds: session.expiresInSeconds, user: request.admin };
  });
}
