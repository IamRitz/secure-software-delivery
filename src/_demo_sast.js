// THIS IS A DELIBERATE TEST FIXTURE FOR A CI/CD SECURITY DEMO. NOT REAL. NOT PRODUCTION CODE. See security/fixtures/README.md.

import { exec } from 'node:child_process';

// Deliberately unsafe: untrusted request data reaches a command shell.
// This module is never imported by the application.
export function demoCommandInjection(request, response) {
  exec(request.query.command, (_error, stdout) => response.send(stdout));
}
