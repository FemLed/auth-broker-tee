export function jsonResponse(res, status, body) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

export function textResponse(res, status, body) {
  res.writeHead(status, { "Content-Type": "text/plain" });
  res.end(body);
}

export function redirectResponse(res, location) {
  res.writeHead(302, { Location: location });
  res.end();
}
