// Same baseline switch + an equality bypass route that is NOT in the
// allowlist. The checker must catch the bypass even though every
// allowlisted route is still present.
function main(url, req, res) {
  if (req.url === "/secret-backdoor") return leak();
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
