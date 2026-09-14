const buckets = new Map();

export function rateLimit({ windowMs, limit, key }) {
  const now = Date.now();
  const bucketKey = key;
  let b = buckets.get(bucketKey);
  if (!b || b.resetAt <= now) {
    b = { count: 0, resetAt: now + windowMs };
    buckets.set(bucketKey, b);
  }
  b.count += 1;
  return {
    allowed: b.count <= limit,
    remaining: Math.max(0, limit - b.count),
    retryAfterMs: Math.max(0, b.resetAt - now),
  };
}

setInterval(() => {
  const now = Date.now();
  for (const [key, b] of buckets) if (b.resetAt <= now) buckets.delete(key);
}, 60_000).unref();
