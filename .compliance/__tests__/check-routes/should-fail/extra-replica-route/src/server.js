// Should fail: the replica-port switch serves a route that is not allowlisted.
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

function replicaPort(url, req, res) {
  switch (url.pathname) {
    case "/health":
      return ok(res);
    case "/replica/manifest":
      return manifest(res);
    case "/replica/export":
      return exportState(res);
    default:
      return notFound(res);
  }
}
