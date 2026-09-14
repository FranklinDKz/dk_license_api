import { config } from '../lib/config.js';
import { rateLimit } from '../lib/rate-limit.js';
import { activateFiveM, deactivateFiveM, heartbeatFiveM } from '../services/licenses.js';

export async function fivemRoutes(app) {
  const limited = async (request, reply) => {
    const rl = rateLimit({ windowMs: 60_000, limit: config.security.fivemLimit, key: `fivem:${request.ip}` });
    if (!rl.allowed) return reply.code(429).send({ ok: false, error: 'RATE_LIMIT' });
  };

  app.post('/api/v1/fivem/activate', { preHandler: limited }, async (request, reply) => {
    const { key, productCode, instanceId } = request.body || {};
    const result = await activateFiveM({ key, productCode, instanceId, ip: request.ip });
    return result.ok ? result : reply.code(result.status || 400).send(result);
  });

  app.post('/api/v1/fivem/heartbeat', { preHandler: limited }, async (request, reply) => {
    const { sessionToken, instanceId } = request.body || {};
    const result = await heartbeatFiveM({ sessionToken, instanceId, ip: request.ip });
    return result.ok ? result : reply.code(result.status || 400).send(result);
  });

  app.post('/api/v1/fivem/deactivate', { preHandler: limited }, async (request, reply) => {
    const { sessionToken, instanceId } = request.body || {};
    const result = await deactivateFiveM({ sessionToken, instanceId, ip: request.ip });
    return result.ok ? result : reply.code(result.status || 400).send(result);
  });
}
