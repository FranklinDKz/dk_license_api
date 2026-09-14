const int = (name, fallback) => Number.parseInt(process.env[name] || String(fallback), 10);
const bool = (name, fallback = false) => {
  const v = process.env[name];
  if (v == null) return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(v).toLowerCase());
};
const req = (name) => {
  const value = process.env[name];
  if (!value) throw new Error(`Variável obrigatória ausente: ${name}`);
  return value;
};

export const config = {
  api: {
    host: process.env.API_HOST || '0.0.0.0',
    port: int('PORT', int('API_PORT', 3210)),
    publicUrl: process.env.API_PUBLIC_URL
      || process.env.RENDER_EXTERNAL_URL
      || (process.env.KOYEB_PUBLIC_DOMAIN ? `https://${process.env.KOYEB_PUBLIC_DOMAIN}` : 'http://127.0.0.1:3210'),
    panelOrigin: process.env.PANEL_ORIGIN || 'http://127.0.0.1:5500',
    trustProxy: bool('TRUST_PROXY', false),
    cookieSecure: bool('COOKIE_SECURE', false),
    cookieSameSite: process.env.COOKIE_SAME_SITE || (bool('COOKIE_SECURE', false) ? 'None' : 'Strict'),
  },
  db: {
    host: process.env.DB_HOST || '127.0.0.1',
    port: int('DB_PORT', 3306),
    database: process.env.DB_NAME || 'dk_license',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD ?? '',
    connectionLimit: int('DB_CONNECTION_LIMIT', 10),
    ssl: bool('DB_SSL', false),
    sslCaBase64: process.env.DB_SSL_CA_BASE64 || '',
    sslRejectUnauthorized: bool('DB_SSL_REJECT_UNAUTHORIZED', true),
  },
  security: {
    jwtSecret: req('JWT_SECRET'),
    botServiceToken: req('BOT_SERVICE_TOKEN'),
    licensePepper: req('LICENSE_PEPPER'),
    loginLimit: int('LOGIN_RATE_LIMIT_PER_15M', 10),
    fivemLimit: int('FIVEM_RATE_LIMIT_PER_MIN', 120),
    adminSessionHours: Math.max(1, Math.min(168, int('ADMIN_SESSION_HOURS', 24))),
  },
  rules: {
    requestLimitPerIp: int('REQUEST_LIMIT_PER_IP', 2),
    defaultIpChangeLimit: int('DEFAULT_IP_CHANGE_LIMIT', 2),
    sessionTtlSeconds: int('SESSION_TTL_SECONDS', 180),
    heartbeatGraceSeconds: int('HEARTBEAT_GRACE_SECONDS', 180),
  },
  discord: {
    defaultProductRoleId: process.env.DEFAULT_DISCORD_PRODUCT_ROLE_ID || '1524550741312929812',
  },
  root: {
    email: process.env.ROOT_EMAIL || 'admin@localhost',
    password: req('ROOT_PASSWORD'),
    name: process.env.ROOT_NAME || 'DK RP',
    orgName: process.env.ROOT_ORG_NAME || 'Sudo Development',
  },
};
