// Entry point: bring the forge up, announce its port to the trial env, then
// sit and serve until the env says the trial is over.
//
// The env owns port 8080, so this process binds port 0 and lets the kernel
// choose. Registration is a single POST; the done poll is a plain loop with a
// growing pause between attempts. Nothing here exits early: the process only
// ends when the env answers {"done": true}, and then it exits 0.

import { createApp } from './app.ts';

const envOrigin = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');
if (envOrigin === '') {
  process.stderr.write('MAKEFUN_ENV_URL is not set, so there is no env to register with\n');
  process.exit(1);
}

function pause(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function backoff(attempt: number): number {
  return Math.min(2000, 250 * 2 ** Math.min(attempt, 8));
}

async function announce(port: number): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const answer = await fetch(`${envOrigin}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(30000),
      });
      if (answer.status === 200 || answer.status === 409) return;
      if (answer.status === 400 || answer.status === 405) {
        throw new Error(`register refused with HTTP ${answer.status}`);
      }
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('register refused')) throw err;
    }
    await pause(backoff(attempt));
  }
}

async function waitUntilDone(): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const answer = await fetch(`${envOrigin}/done`, { signal: AbortSignal.timeout(30000) });
      if (answer.ok) {
        const body = (await answer.json()) as { done?: unknown };
        if (body.done === true) return;
      }
    } catch {
      // The env is not answering yet; keep polling.
    }
    await pause(backoff(attempt));
  }
}

async function run(): Promise<void> {
  const server = createApp();
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, () => resolve());
  });
  const bound = server.address();
  if (bound === null || typeof bound === 'string') {
    throw new Error('the server did not bind a TCP port');
  }
  process.stdout.write(`listening on port ${bound.port}\n`);
  await announce(bound.port);
  process.stdout.write('registered; waiting for done\n');
  await waitUntilDone();
  // Let any in-flight answer finish before the process goes away.
  await new Promise<void>((resolve) => server.close(() => resolve()));
  process.stdout.write('done\n');
}

try {
  await run();
  process.exit(0);
} catch (err) {
  process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
}
