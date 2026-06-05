// Allowlist requires /refresh but the switch does not implement it.
// The checker must flag the missing main-server route.
function main(url, req, res) {
  switch (url.pathname) {
    case "/login":
      return handleLogin();
    case "/health":
      return ok(res);
    default:
      return notFound(res);
  }
}

function healthServer(req) {
  if (req.url === "/health") return true;
  return false;
}
