// Replica-port fixture: the public switch and the replica-port switch each
// cover exactly their allowlisted routes.
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
    default:
      return notFound(res);
  }
}
