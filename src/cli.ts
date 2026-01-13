#!/usr/bin/env node
// SLOP Auditor CLI - Visualize audit results

import { visualize, visualizeState, visualizeCompact } from './visualizer/index.js';
import type { AuditorOutput } from './types/events.js';

const SLOP_URL = process.env.SLOP_URL ?? 'http://127.0.0.1:3000';

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  switch (command) {
    case 'status':
      await showStatus();
      break;
    case 'audit':
      await runAudit(args.slice(1));
      break;
    case 'logs':
      await showLogs();
      break;
    case 'watch':
      await watchMode();
      break;
    default:
      showHelp();
  }
}

async function showStatus() {
  try {
    const res = await fetch(`${SLOP_URL}/info`);
    const info = await res.json();
    console.log('\n╔═══════════════════════════════════╗');
    console.log('║     SLOP AUDITOR STATUS           ║');
    console.log('╚═══════════════════════════════════╝\n');
    console.log(`Server:    ${SLOP_URL}`);
    console.log(`Name:      ${info.name}`);
    console.log(`Version:   ${info.version}`);
    console.log(`Tools:     ${info.tools.join(', ')}`);
    console.log(`Endpoints: ${info.endpoints.join(', ')}`);
    console.log('');
  } catch (err) {
    console.error('❌ Cannot connect to SLOP server at', SLOP_URL);
    process.exit(1);
  }
}

async function runAudit(args: string[]) {
  const inputFile = args[0];

  if (!inputFile) {
    // Run interactive demo
    const demoInput = {
      tool: 'audit',
      arguments: {
        change_event: {
          id: 'demo-' + Date.now(),
          type: 'pull_request',
          environment: 'staging',
          repo: 'demo/app',
          commit: 'a'.repeat(40),
          files_changed: ['src/auth/login.ts'],
          diff: '+const API_KEY = "secret123";'
        },
        evidence_bundle: {
          vuln_scan: 'critical: 1\nhigh: 2'
        },
        policy_context: {
          critical_assets: ['auth'],
          risk_tolerance: 'low'
        }
      }
    };

    console.log('\n🔍 Running demo audit...\n');

    const res = await fetch(`${SLOP_URL}/tools`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(demoInput)
    });

    const data = await res.json();
    const output = data.result as AuditorOutput;

    console.log(visualize(output));
    console.log('\n' + visualizeState(output.agent_state));
    console.log('\n' + visualizeCompact(output));
  } else {
    // Load from file
    const { readFileSync } = await import('fs');
    const input = JSON.parse(readFileSync(inputFile, 'utf-8'));

    const payload = input.tool ? input : { tool: 'audit', arguments: input };

    const res = await fetch(`${SLOP_URL}/tools`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const data = await res.json();
    const output = data.result as AuditorOutput;

    console.log(visualize(output));
  }
}

async function showLogs() {
  const res = await fetch(`${SLOP_URL}/memory`);
  const data = await res.json();

  console.log('\n╔═══════════════════════════════════╗');
  console.log('║       AUDIT LOG ENTRIES           ║');
  console.log('╚═══════════════════════════════════╝\n');

  if (data.keys.length === 0) {
    console.log('  No audit logs found.');
  } else {
    for (const key of data.keys) {
      const parts = key.split(':');
      console.log(`  • ${parts[1]} (${new Date(parseInt(parts[2])).toISOString()})`);
    }
  }
  console.log('');
}

async function watchMode() {
  console.log('\n👁️  SLOP Auditor Watch Mode');
  console.log('   Monitoring for new audits...\n');

  let lastCount = 0;

  setInterval(async () => {
    try {
      const res = await fetch(`${SLOP_URL}/memory`);
      const data = await res.json();

      if (data.keys.length > lastCount) {
        const newKeys = data.keys.slice(lastCount);
        for (const key of newKeys) {
          const entryRes = await fetch(`${SLOP_URL}/memory?key=${encodeURIComponent(key)}`);
          const entry = await entryRes.json();

          if (entry.value) {
            console.log('\n━━━ NEW AUDIT ━━━');
            console.log(visualizeCompact(entry.value as AuditorOutput));
          }
        }
        lastCount = data.keys.length;
      }
    } catch {
      // Ignore errors in watch mode
    }
  }, 2000);
}

function showHelp() {
  console.log(`
SLOP Auditor CLI

Usage:
  npx tsx src/cli.ts <command> [options]

Commands:
  status          Show server status
  audit [file]    Run audit (demo if no file provided)
  logs            Show audit log entries
  watch           Watch for new audits

Environment:
  SLOP_URL        Server URL (default: http://127.0.0.1:3000)

Examples:
  npx tsx src/cli.ts status
  npx tsx src/cli.ts audit
  npx tsx src/cli.ts audit examples/test-payload.json
  npx tsx src/cli.ts logs
  npx tsx src/cli.ts watch
`);
}

main().catch(console.error);
