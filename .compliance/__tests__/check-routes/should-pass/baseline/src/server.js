// Baseline fixture: switch covers all allowlisted main routes; healthServer
// uses an equality test that matches the allowlisted health route.
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
