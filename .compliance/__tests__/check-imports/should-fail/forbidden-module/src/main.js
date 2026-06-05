// child_process is in _explicitly_forbidden_even_if_added_to_allowlist.
// The checker must reject this import.
import { spawn } from "node:child_process";
spawn("date");
