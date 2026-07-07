export function jsonResponse(res, status, body) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

// Wraps `new URL(req.url, "https://" + Host)` so a Host header that is not a
// valid URL authority (internet scanners routinely send these) yields null
// instead of a throw. Inside an async request handler that throw becomes an
// unhandled promise rejection, which kills the process; each crash-reboot
// re-mints TLS and burns a Let's Encrypt issuance (cause of the 2026-07-07
// boot-loop outage). Callers map null to a 400 response.
export function parseRequestUrl(req) {
  try {
    return new URL(req.url, `https://${req.headers.host}`);
  } catch {
    return null;
  }
}

export function textResponse(res, status, body) {
  res.writeHead(status, { "Content-Type": "text/plain" });
  res.end(body);
}

export function redirectResponse(res, location) {
  res.writeHead(302, { Location: location });
  res.end();
}
