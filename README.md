# SLOP Auditor

A security audit pipeline built on the SLOP (Simple Lightweight Orchestration Protocol) framework. Provides automated security analysis for code changes with a 3D visualization control plane.

## Quick Start

```bash
# Install dependencies
npm install

# Build the project
npm run build

# Start the SLOP server
npm start

# In another terminal, start the 3D visualizer
npm run visualizer

# Open http://127.0.0.1:8080 in your browser
```

## Architecture

```
slop-auditor/
├── src/
│   ├── index.ts           # Main entry point - starts SLOP server
│   ├── cli.ts             # CLI tool for interacting with the auditor
│   ├── serve-visualizer.ts # Serves the 3D web UI
│   ├── client/            # High-level client SDK
│   ├── pipeline/          # Extensible analysis pipeline
│   ├── auditor/           # Core audit logic
│   ├── schemas/           # JSON schema validation
│   ├── slop/              # SLOP server/client implementation
│   ├── types/             # TypeScript type definitions
│   └── visualizer/        # Console-based visualization
├── visualizer/            # 3D Web UI (Three.js)
└── examples/              # Sample inputs and usage
```

## Usage

### 1. Start the Server

```bash
# Default port 3000
npm start

# Custom port
SLOP_PORT=4000 npm start
```

### 2. Start the 3D Visualizer

```bash
# Default port 8080
npm run visualizer

# Custom port
VISUALIZER_PORT=9000 npm run visualizer
```

### 3. Run Audits via CLI

```bash
# Show server status
npx tsx src/cli.ts status

# Run demo audit
npx tsx src/cli.ts audit

# Audit from file
npx tsx src/cli.ts audit examples/test-payload.json

# View audit logs
npx tsx src/cli.ts logs

# Watch for new audits
npx tsx src/cli.ts watch
```

### 4. Run Audits via HTTP API

```bash
# Run an audit
curl -X POST http://127.0.0.1:3000/tools \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "audit",
    "arguments": {
      "change_event": {
        "id": "pr-123",
        "type": "pull_request",
        "environment": "staging",
        "repo": "acme/webapp",
        "commit": "abc123...",
        "files_changed": ["src/auth/login.ts"],
        "diff": "+const API_KEY = \"secret\";"
      },
      "evidence_bundle": {
        "vuln_scan": "critical: 1\nhigh: 2"
      },
      "policy_context": {
        "critical_assets": ["auth", "billing"],
        "risk_tolerance": "low"
      }
    }
  }'

# Get server info
curl http://127.0.0.1:3000/info

# List audit logs
curl http://127.0.0.1:3000/memory

# Get specific audit
curl "http://127.0.0.1:3000/memory?key=audit:pr-123:1234567890"
```

### 5. Use the Client SDK

```typescript
import { AuditClient, createPullRequestEvent } from 'slop-auditor';

const client = new AuditClient({
  serverUrl: 'http://127.0.0.1:3000'
});

// Check server health
const healthy = await client.isHealthy();

// Run an audit
const result = await client.audit({
  changeEvent: createPullRequestEvent(
    'acme/webapp',
    'abc123...',
    ['src/auth/login.ts'],
    '+const API_KEY = "secret";',
    'staging'
  ),
  evidenceBundle: {
    vuln_scan: 'critical: 1\nhigh: 2'
  },
  policyContext: {
    critical_assets: ['auth', 'billing'],
    risk_tolerance: 'low'
  }
});

console.log(result.output?.agent_state); // 'blocked', 'escalated', etc.

// Watch for audits
for await (const audit of client.watchAudits()) {
  console.log('New audit:', audit.agent_state);
}
```

### 6. Custom Pipeline Stages

```typescript
import { SecurityPipeline, AnalysisStage, PipelineContext } from 'slop-auditor';

// Create custom analysis stage
class CustomSecurityStage implements AnalysisStage {
  name = 'custom-check';
  description = 'My custom security check';

  analyze(ctx: PipelineContext): void {
    // Access input data
    const { change_event } = ctx.input;

    // Add findings
    if (someCondition) {
      ctx.events.push({
        event_type: 'finding_raised',
        target: 'self',
        payload: {
          severity: 'high',
          claim: 'Custom security issue detected',
          attack_path: ['Step 1', 'Step 2'],
          affected_assets: ['asset1'],
          evidence_refs: [{ type: 'diff', pointer: 'file.ts' }],
          assurance_break: ['integrity'],
          confidence: 0.9
        },
        timestamp: new Date().toISOString()
      });
    }

    // Add assumptions/uncertainties
    ctx.assumptions.push('Assuming X is configured correctly');
    ctx.uncertainties.push('Cannot verify Y without manual review');
  }
}

// Use custom pipeline
const pipeline = new SecurityPipeline();
pipeline.addStage(new CustomSecurityStage());

const result = await pipeline.execute(input);
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/info` | GET | Server information |
| `/tools` | GET | List available tools |
| `/tools` | POST | Execute a tool (audit) |
| `/memory` | GET | List or retrieve audit logs |
| `/memory` | POST | Store data (internal use) |

## Input Schema

```typescript
interface AuditorInput {
  change_event: {
    id: string;
    type: 'pull_request' | 'deploy' | 'infra_change';
    environment: 'dev' | 'staging' | 'prod';
    repo: string;
    commit: string;
    files_changed: string[];
    diff: string;
  };
  evidence_bundle: {
    sbom?: string;
    vuln_scan?: string;
    sast_results?: string;
    iac_scan?: string;
    provenance?: string;
    runtime_delta?: string;
  };
  policy_context: {
    critical_assets: string[];
    risk_tolerance: 'low' | 'medium' | 'high';
  };
}
```

## Output Schema

```typescript
interface AuditorOutput {
  agent_id: string;          // 'exploit-reviewer'
  agent_state: AgentState;   // 'idle' | 'analyzing' | 'conflict' | 'escalated' | 'blocked'
  events: AuditEvent[];
  meta: {
    assumptions: string[];
    uncertainties: string[];
  };
}

interface AuditEvent {
  event_type: 'analysis_started' | 'finding_raised' | 'conflict_detected' | 'escalation_triggered';
  target: string;
  payload: {
    severity: 'low' | 'medium' | 'high' | 'critical';
    claim: string;
    attack_path: string[];
    affected_assets: string[];
    evidence_refs: Array<{ type: string; pointer: string }>;
    assurance_break: Array<'integrity' | 'access_control' | 'isolation' | 'auditability'>;
    confidence: number;  // 0.0 - 1.0
  };
  timestamp: string;  // ISO8601
}
```

## Built-in Security Checks

1. **Secrets Detection** - Detects hardcoded API keys, passwords, tokens, private keys
2. **Vulnerability Scan** - Parses vulnerability scan results for critical/high findings
3. **Critical Asset Monitor** - Alerts when critical asset paths are modified
4. **Infrastructure Change** - Flags IaC/Terraform changes for review
5. **Production Deploy Guard** - Warns about direct production deployments

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SLOP_PORT` | 3000 | SLOP server port |
| `SLOP_BUS_URL` | - | External SLOP bus URL (optional) |
| `VISUALIZER_PORT` | 8080 | 3D visualizer web server port |
| `SLOP_URL` | http://127.0.0.1:3000 | CLI target server URL |

## 3D Visualizer Features

The web-based 3D control plane provides:

- Real-time agent state visualization (idle, analyzing, conflict, escalated, blocked)
- Interactive Three.js scene with orbit controls
- Finding markers positioned around the agent
- Quick-action presets for common scenarios
- Audit history browser
- Custom audit submission form
- Live polling of SLOP server state

## Development

```bash
# Run in development mode
npm run dev

# Run both server and visualizer
npm run full

# Build TypeScript
npm run build

# Run tests
npm test
```

## License

MIT
