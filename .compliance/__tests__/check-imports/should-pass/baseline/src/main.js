// Only allowlisted imports.
import crypto from "node:crypto";
import http from "node:http";

export function noop() { return crypto.randomUUID() + http.METHODS[0]; }
