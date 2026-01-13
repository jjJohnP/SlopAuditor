// Local System Scanner - Audit the local machine for security issues
// Uses REAL security tools: gitleaks, trivy, semgrep, npm audit
// Scans: secrets in files, package vulnerabilities, git repos, env files

import { readFileSync, readdirSync, existsSync, statSync, writeFileSync, mkdtempSync, rmSync } from 'fs';
import { join, extname, basename } from 'path';
import { execSync, spawnSync } from 'child_process';
import { tmpdir } from 'os';
import type { AuditorInput, ChangeEvent, EvidenceBundle } from '../types/events.js';

// ============ REAL SECURITY TOOL INTEGRATIONS ============

interface GitleaksResult {
  Description: string;
  File: string;
  StartLine: number;
  EndLine: number;
  Match: string;
  Secret: string;
  RuleID: string;
  Entropy: number;
  Commit?: string;
}

interface TrivyVuln {
  VulnerabilityID: string;
  PkgName: string;
  InstalledVersion: string;
  FixedVersion?: string;
  Severity: string;
  Title: string;
  Description?: string;
}

interface TrivyResult {
  Results?: Array<{
    Target: string;
    Vulnerabilities?: TrivyVuln[];
  }>;
}

interface SemgrepResult {
  results?: Array<{
    check_id: string;
    path: string;
    start: { line: number };
    end: { line: number };
    extra: {
      message: string;
      severity: string;
      metadata?: { cwe?: string[] };
    };
  }>;
}

interface NpmAuditResult {
  vulnerabilities?: Record<string, {
    name: string;
    severity: string;
    range: string;
    via: unknown[];
  }>;
}

// Check if a tool is available
function isToolAvailable(tool: string): boolean {
  try {
    const result = spawnSync(tool, ['--version'], { encoding: 'utf-8', timeout: 5000 });
    return result.status === 0;
  } catch {
    return false;
  }
}

// Run gitleaks for secrets detection
function runGitleaks(targetPath: string): SecretFinding[] {
  const findings: SecretFinding[] = [];

  if (!isToolAvailable('gitleaks')) {
    console.log('[SCANNER] gitleaks not available, skipping');
    return findings;
  }

  try {
    console.log('[SCANNER] Running gitleaks...');
    const reportPath = join(tmpdir(), `gitleaks-${Date.now()}.json`);

    // Run gitleaks
    spawnSync('gitleaks', [
      'detect',
      '--source', targetPath,
      '--report-format', 'json',
      '--report-path', reportPath,
      '--no-git',
      '--exit-code', '0'
    ], { encoding: 'utf-8', timeout: 120000 });

    if (existsSync(reportPath)) {
      const report = JSON.parse(readFileSync(reportPath, 'utf-8')) as GitleaksResult[];

      for (const finding of report) {
        findings.push({
          file: finding.File,
          line: finding.StartLine,
          type: finding.RuleID || finding.Description,
          snippet: `[REDACTED - ${finding.Description}]`,
          severity: finding.Entropy > 4 ? 'critical' : 'high'
        });
      }

      // Cleanup
      try { rmSync(reportPath); } catch {}
    }

    console.log(`[SCANNER] gitleaks found ${findings.length} secrets`);
  } catch (err) {
    console.error('[SCANNER] gitleaks error:', err);
  }

  return findings;
}

// Run trivy for vulnerability scanning
function runTrivy(targetPath: string): PackageFinding[] {
  const findings: PackageFinding[] = [];

  if (!isToolAvailable('trivy')) {
    console.log('[SCANNER] trivy not available, skipping');
    return findings;
  }

  try {
    console.log('[SCANNER] Running trivy...');

    const result = spawnSync('trivy', [
      'fs',
      '--format', 'json',
      '--scanners', 'vuln',
      '--quiet',
      targetPath
    ], { encoding: 'utf-8', timeout: 180000, maxBuffer: 50 * 1024 * 1024 });

    if (result.stdout) {
      const report = JSON.parse(result.stdout) as TrivyResult;

      if (report.Results) {
        for (const target of report.Results) {
          if (target.Vulnerabilities) {
            for (const vuln of target.Vulnerabilities) {
              findings.push({
                name: vuln.PkgName,
                version: vuln.InstalledVersion,
                vulnerabilities: 1,
                severity: normalizeSeverity(vuln.Severity),
                vulnId: vuln.VulnerabilityID,
                title: vuln.Title,
                fixedVersion: vuln.FixedVersion
              });
            }
          }
        }
      }
    }

    console.log(`[SCANNER] trivy found ${findings.length} vulnerabilities`);
  } catch (err) {
    console.error('[SCANNER] trivy error:', err);
  }

  return findings;
}

// Run semgrep for SAST
function runSemgrep(targetPath: string): Array<{ file: string; line: number; rule: string; message: string; severity: string }> {
  const findings: Array<{ file: string; line: number; rule: string; message: string; severity: string }> = [];

  if (!isToolAvailable('semgrep')) {
    console.log('[SCANNER] semgrep not available, skipping');
    return findings;
  }

  try {
    console.log('[SCANNER] Running semgrep...');

    const result = spawnSync('semgrep', [
      'scan',
      '--config', 'auto',
      '--json',
      '--quiet',
      targetPath
    ], { encoding: 'utf-8', timeout: 300000, maxBuffer: 50 * 1024 * 1024 });

    if (result.stdout) {
      try {
        const report = JSON.parse(result.stdout) as SemgrepResult;

        if (report.results) {
          for (const finding of report.results) {
            findings.push({
              file: finding.path,
              line: finding.start.line,
              rule: finding.check_id,
              message: finding.extra.message,
              severity: finding.extra.severity || 'WARNING'
            });
          }
        }
      } catch {}
    }

    console.log(`[SCANNER] semgrep found ${findings.length} issues`);
  } catch (err) {
    console.error('[SCANNER] semgrep error:', err);
  }

  return findings;
}

// Run npm audit for package vulnerabilities
function runNpmAudit(targetPath: string): PackageFinding[] {
  const findings: PackageFinding[] = [];
  const packageJsonPath = join(targetPath, 'package.json');

  if (!existsSync(packageJsonPath)) {
    return findings;
  }

  try {
    console.log('[SCANNER] Running npm audit...');

    const result = spawnSync('npm', ['audit', '--json'], {
      cwd: targetPath,
      encoding: 'utf-8',
      timeout: 60000,
      maxBuffer: 10 * 1024 * 1024,
      shell: true
    });

    if (result.stdout) {
      try {
        const report = JSON.parse(result.stdout) as NpmAuditResult;

        if (report.vulnerabilities) {
          for (const [name, vuln] of Object.entries(report.vulnerabilities)) {
            findings.push({
              name,
              version: vuln.range || 'unknown',
              vulnerabilities: 1,
              severity: normalizeSeverity(vuln.severity)
            });
          }
        }
      } catch {}
    }

    console.log(`[SCANNER] npm audit found ${findings.length} vulnerabilities`);
  } catch (err) {
    console.error('[SCANNER] npm audit error:', err);
  }

  return findings;
}

function normalizeSeverity(sev: string): 'critical' | 'high' | 'medium' | 'low' {
  const s = sev?.toLowerCase() || '';
  if (s === 'critical' || s === 'crit') return 'critical';
  if (s === 'high' || s === 'h' || s === 'error') return 'high';
  if (s === 'medium' || s === 'med' || s === 'moderate' || s === 'warning') return 'medium';
  return 'low';
}

// ============ END REAL TOOL INTEGRATIONS ============

export interface LocalScanConfig {
  targetPath: string;
  scanSecrets?: boolean;
  scanPackages?: boolean;
  scanGit?: boolean;
  scanEnvFiles?: boolean;
  maxDepth?: number;
  excludePatterns?: string[];
}

export interface DiscoveredService {
  id: string;
  name: string;
  type: 'database' | 'cache' | 'cloud' | 'api' | 'messaging' | 'storage' | 'auth' | 'monitoring';
  source: string;  // Where it was discovered (file path or config)
  connectionInfo?: string;  // Masked connection string
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
}

// Discovered module/directory in the codebase
export interface DiscoveredModule {
  id: string;
  name: string;
  path: string;
  type: 'source' | 'component' | 'service' | 'api' | 'lib' | 'config' | 'test' | 'infra' | 'docs';
  fileCount: number;
  files: string[];
  imports: string[];  // Other modules this imports from
  exports: string[];  // What this module exports
}

export interface LocalScanResult {
  path: string;
  timestamp: string;
  secrets: SecretFinding[];
  packages: PackageFinding[];
  sastFindings: SastFinding[];              // SAST findings from semgrep
  gitInfo: GitInfo | null;
  envFiles: EnvFileFinding[];
  systemInfo: SystemInfo;
  discoveredServices: DiscoveredService[];  // Auto-discovered external services
  discoveredModules: DiscoveredModule[];    // Auto-discovered code modules/directories
  toolsUsed: string[];                      // Which real security tools were run
}

export interface SecretFinding {
  file: string;
  line: number;
  type: string;
  snippet: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface PackageFinding {
  name: string;
  version: string;
  vulnerabilities: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  vulnId?: string;      // CVE or vulnerability ID
  title?: string;       // Vulnerability title
  fixedVersion?: string; // Version that fixes the vulnerability
}

// SAST finding from Semgrep
export interface SastFinding {
  file: string;
  line: number;
  rule: string;
  message: string;
  severity: string;
}

export interface GitInfo {
  branch: string;
  remoteUrl?: string;
  uncommittedChanges: number;
  lastCommit?: string;
}

export interface EnvFileFinding {
  file: string;
  variables: string[];
  hasSecrets: boolean;
}

export interface SystemInfo {
  platform: string;
  hostname: string;
  user: string;
  nodeVersion: string;
  cwd: string;
}

// Secret detection patterns - STRICT: only match actual values, not variable names
const SECRET_PATTERNS = [
  // Only match when there's an actual value in quotes after = or :
  { name: 'API Key', regex: /api[_-]?key\s*[=:]\s*['"]([A-Za-z0-9_\-]{20,})['"](?!\s*[,;]?\s*$)/gi, severity: 'high' as const },
  { name: 'Secret Value', regex: /secret\s*[=:]\s*['"]([A-Za-z0-9_\-]{16,})['"](?!\s*[,;]?\s*$)/gi, severity: 'high' as const },
  { name: 'Password', regex: /password\s*[=:]\s*['"]([^'"]{8,})['"](?!\s*[,;]?\s*$)/gi, severity: 'critical' as const },
  // These are definitive patterns - actual secret formats
  { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/g, severity: 'critical' as const },
  { name: 'AWS Secret Key', regex: /[A-Za-z0-9\/+=]{40}(?=\s|$|")/g, severity: 'critical' as const },
  { name: 'Private Key', regex: /-----BEGIN\s+(RSA|EC|OPENSSH|PGP|ENCRYPTED)?\s*PRIVATE\s+KEY-----/g, severity: 'critical' as const },
  { name: 'GitHub Token', regex: /gh[pousr]_[A-Za-z0-9_]{36,}/g, severity: 'critical' as const },
  { name: 'GitLab Token', regex: /glpat-[A-Za-z0-9_-]{20,}/g, severity: 'critical' as const },
  { name: 'Slack Token', regex: /xox[baprs]-[A-Za-z0-9-]{10,}/g, severity: 'high' as const },
  { name: 'Stripe Key', regex: /sk_live_[A-Za-z0-9]{24,}/g, severity: 'critical' as const },
  { name: 'Stripe Test Key', regex: /sk_test_[A-Za-z0-9]{24,}/g, severity: 'medium' as const },
  // Connection strings with actual credentials (user:pass@host pattern)
  { name: 'Database URL', regex: /(mongodb|postgres|mysql|redis|amqp):\/\/[^:]+:[^@]+@[^\s"']+/gi, severity: 'critical' as const },
  // Bearer tokens in actual use
  { name: 'Bearer Token', regex: /["']Bearer\s+[A-Za-z0-9_\-\.]{20,}["']/gi, severity: 'high' as const },
  // JWT tokens (actual tokens, not patterns)
  { name: 'JWT Token', regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}/g, severity: 'medium' as const },
  // OpenAI API Key
  { name: 'OpenAI Key', regex: /sk-[A-Za-z0-9]{32,}/g, severity: 'high' as const },
];

// Files/patterns to SKIP for secret scanning (test files, examples, etc.)
const SKIP_SECRET_SCAN_PATTERNS = [
  /example/i, /sample/i, /test/i, /mock/i, /fixture/i, /\.test\./i, /\.spec\./i,
  /\.d\.ts$/, /\.map$/, /\.min\./
];

// Files to scan for secrets
const FILES_TO_SCAN = [
  '.env', '.env.local', '.env.development', '.env.production',
  'config.json', 'config.js', 'config.ts',
  'settings.json', 'settings.js',
  'credentials.json', 'secrets.json',
  '.npmrc', '.yarnrc',
];

// Service detection patterns - discover what technologies are used
const SERVICE_PATTERNS: Array<{
  name: string;
  id: string;
  type: DiscoveredService['type'];
  patterns: RegExp[];
  severity: DiscoveredService['severity'];
}> = [
  // Databases
  { name: 'MongoDB', id: 'mongodb', type: 'database', severity: 'high',
    patterns: [/mongodb(\+srv)?:\/\//gi, /mongoose\.connect/gi, /MongoClient/gi, /MONGO_URI/gi, /MONGODB_URL/gi] },
  { name: 'PostgreSQL', id: 'postgres', type: 'database', severity: 'high',
    patterns: [/postgres(ql)?:\/\//gi, /pg\.connect/gi, /PG_HOST/gi, /POSTGRES_/gi, /DATABASE_URL.*postgres/gi] },
  { name: 'MySQL', id: 'mysql', type: 'database', severity: 'high',
    patterns: [/mysql:\/\//gi, /mysql\.createConnection/gi, /MYSQL_/gi] },
  { name: 'Redis', id: 'redis', type: 'cache', severity: 'medium',
    patterns: [/redis:\/\//gi, /createClient.*redis/gi, /REDIS_URL/gi, /REDIS_HOST/gi, /ioredis/gi] },
  { name: 'SQLite', id: 'sqlite', type: 'database', severity: 'low',
    patterns: [/sqlite3?/gi, /\.sqlite/gi, /better-sqlite/gi] },
  { name: 'Elasticsearch', id: 'elasticsearch', type: 'database', severity: 'medium',
    patterns: [/elasticsearch/gi, /ELASTIC_/gi, /@elastic\/elasticsearch/gi] },

  // Cloud Services
  { name: 'AWS', id: 'aws', type: 'cloud', severity: 'critical',
    patterns: [/aws-sdk/gi, /AKIA[0-9A-Z]{16}/g, /AWS_ACCESS_KEY/gi, /AWS_SECRET/gi, /s3\.amazonaws/gi, /dynamodb/gi, /lambda/gi] },
  { name: 'Google Cloud', id: 'gcp', type: 'cloud', severity: 'critical',
    patterns: [/@google-cloud/gi, /GOOGLE_APPLICATION_CREDENTIALS/gi, /googleapis/gi, /firestore/gi, /gcloud/gi] },
  { name: 'Azure', id: 'azure', type: 'cloud', severity: 'critical',
    patterns: [/@azure/gi, /AZURE_/gi, /\.azure\./gi, /blob\.core\.windows/gi] },
  { name: 'Firebase', id: 'firebase', type: 'cloud', severity: 'high',
    patterns: [/firebase/gi, /FIREBASE_/gi, /firebaseConfig/gi] },
  { name: 'Supabase', id: 'supabase', type: 'cloud', severity: 'high',
    patterns: [/supabase/gi, /SUPABASE_/gi, /@supabase\/supabase-js/gi] },

  // APIs & Services
  { name: 'Stripe', id: 'stripe', type: 'api', severity: 'critical',
    patterns: [/stripe/gi, /STRIPE_/gi, /sk_live_/gi, /sk_test_/gi, /pk_live_/gi] },
  { name: 'Twilio', id: 'twilio', type: 'api', severity: 'high',
    patterns: [/twilio/gi, /TWILIO_/gi] },
  { name: 'SendGrid', id: 'sendgrid', type: 'api', severity: 'medium',
    patterns: [/sendgrid/gi, /SENDGRID_/gi, /@sendgrid\/mail/gi] },
  { name: 'OpenAI', id: 'openai', type: 'api', severity: 'high',
    patterns: [/openai/gi, /OPENAI_API_KEY/gi, /sk-[a-zA-Z0-9]{32,}/gi] },

  // Messaging
  { name: 'RabbitMQ', id: 'rabbitmq', type: 'messaging', severity: 'medium',
    patterns: [/amqp:\/\//gi, /rabbitmq/gi, /RABBITMQ_/gi] },
  { name: 'Kafka', id: 'kafka', type: 'messaging', severity: 'medium',
    patterns: [/kafkajs/gi, /KAFKA_/gi, /kafka\.connect/gi] },

  // Auth
  { name: 'Auth0', id: 'auth0', type: 'auth', severity: 'high',
    patterns: [/auth0/gi, /AUTH0_/gi] },
  { name: 'Okta', id: 'okta', type: 'auth', severity: 'high',
    patterns: [/okta/gi, /OKTA_/gi] },
  { name: 'JWT', id: 'jwt', type: 'auth', severity: 'medium',
    patterns: [/jsonwebtoken/gi, /JWT_SECRET/gi, /eyJ[A-Za-z0-9_-]*\./gi] },

  // Storage
  { name: 'S3', id: 's3', type: 'storage', severity: 'high',
    patterns: [/s3\.amazonaws/gi, /AWS_S3_/gi, /S3_BUCKET/gi] },
  { name: 'Cloudflare R2', id: 'r2', type: 'storage', severity: 'high',
    patterns: [/r2\.cloudflarestorage/gi, /R2_/gi] },

  // Monitoring
  { name: 'Datadog', id: 'datadog', type: 'monitoring', severity: 'low',
    patterns: [/datadog/gi, /DD_API_KEY/gi, /dd-trace/gi] },
  { name: 'Sentry', id: 'sentry', type: 'monitoring', severity: 'low',
    patterns: [/sentry/gi, /SENTRY_DSN/gi, /@sentry/gi] },
  { name: 'New Relic', id: 'newrelic', type: 'monitoring', severity: 'low',
    patterns: [/newrelic/gi, /NEW_RELIC_/gi] },
];

// Extensions to scan
const EXTENSIONS_TO_SCAN = ['.js', '.ts', '.json', '.yaml', '.yml', '.env', '.config', '.conf'];

export class LocalScanner {
  private config: LocalScanConfig;

  constructor(config: LocalScanConfig) {
    this.config = {
      scanSecrets: true,
      scanPackages: true,
      scanGit: true,
      scanEnvFiles: true,
      maxDepth: 5,
      excludePatterns: ['node_modules', '.git', 'dist', 'build', '.next', 'coverage'],
      ...config
    };
  }

  async scan(): Promise<LocalScanResult> {
    const toolsUsed: string[] = [];
    const result: LocalScanResult = {
      path: this.config.targetPath,
      timestamp: new Date().toISOString(),
      secrets: [],
      packages: [],
      sastFindings: [],
      gitInfo: null,
      envFiles: [],
      systemInfo: this.getSystemInfo(),
      discoveredServices: [],
      discoveredModules: [],
      toolsUsed: []
    };

    console.log(`[SCANNER] Starting scan of: ${this.config.targetPath}`);

    // ============ SECRETS SCANNING ============
    if (this.config.scanSecrets) {
      // Try gitleaks first (real tool)
      if (isToolAvailable('gitleaks')) {
        console.log('[SCANNER] Using gitleaks for secrets detection');
        const gitleaksFindings = runGitleaks(this.config.targetPath);
        result.secrets.push(...gitleaksFindings);
        toolsUsed.push('gitleaks');
      } else {
        // Fallback to regex-based scanning
        console.log('[SCANNER] gitleaks not available, using regex patterns');
        result.secrets = this.scanForSecrets(this.config.targetPath);
        toolsUsed.push('regex-patterns');
      }
    }

    // ============ PACKAGE VULNERABILITY SCANNING ============
    if (this.config.scanPackages) {
      // Try trivy first (real tool)
      if (isToolAvailable('trivy')) {
        console.log('[SCANNER] Using trivy for vulnerability scanning');
        const trivyFindings = runTrivy(this.config.targetPath);
        result.packages.push(...trivyFindings);
        toolsUsed.push('trivy');
      }

      // Also run npm audit if package.json exists
      const npmAuditFindings = runNpmAudit(this.config.targetPath);
      if (npmAuditFindings.length > 0) {
        // Merge with existing, avoiding duplicates
        for (const finding of npmAuditFindings) {
          if (!result.packages.some(p => p.name === finding.name && p.vulnId === finding.vulnId)) {
            result.packages.push(finding);
          }
        }
        toolsUsed.push('npm-audit');
      }

      // Fallback if no real tools ran
      if (!toolsUsed.includes('trivy') && !toolsUsed.includes('npm-audit')) {
        console.log('[SCANNER] No package scanners available, using basic scan');
        result.packages = await this.scanPackages(this.config.targetPath);
        toolsUsed.push('basic-package-scan');
      }
    }

    // ============ SAST SCANNING ============
    if (isToolAvailable('semgrep')) {
      console.log('[SCANNER] Using semgrep for SAST analysis');
      const semgrepFindings = runSemgrep(this.config.targetPath);
      result.sastFindings = semgrepFindings;
      toolsUsed.push('semgrep');
    } else {
      console.log('[SCANNER] semgrep not available, skipping SAST');
    }

    // ============ GIT INFO ============
    if (this.config.scanGit) {
      result.gitInfo = this.getGitInfo(this.config.targetPath);
    }

    // ============ ENV FILES ============
    if (this.config.scanEnvFiles) {
      result.envFiles = this.scanEnvFiles(this.config.targetPath);
    }

    // ============ SERVICE DISCOVERY ============
    // Always discover services - this builds out the map
    result.discoveredServices = this.discoverServices(this.config.targetPath);

    // ============ MODULE DISCOVERY ============
    // Discover code modules/directories - this maps the codebase structure
    result.discoveredModules = this.discoverModules(this.config.targetPath);

    result.toolsUsed = toolsUsed;

    console.log(`[SCANNER] Scan complete. Tools used: ${toolsUsed.join(', ')}`);
    console.log(`[SCANNER] Found: ${result.secrets.length} secrets, ${result.packages.length} package issues, ${result.sastFindings.length} SAST findings`);

    return result;
  }

  // Discover what services/technologies are used in the codebase
  private discoverServices(dir: string): DiscoveredService[] {
    const discovered = new Map<string, DiscoveredService>();

    // Scan package.json for dependencies
    const pkgPath = join(dir, 'package.json');
    if (existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
        const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };

        for (const pattern of SERVICE_PATTERNS) {
          for (const depName of Object.keys(allDeps)) {
            for (const regex of pattern.patterns) {
              regex.lastIndex = 0;
              if (regex.test(depName)) {
                if (!discovered.has(pattern.id)) {
                  discovered.set(pattern.id, {
                    id: pattern.id,
                    name: pattern.name,
                    type: pattern.type,
                    source: 'package.json',
                    severity: pattern.severity
                  });
                }
                break;
              }
            }
          }
        }
      } catch { /* ignore */ }
    }

    // Scan source files for service usage
    this.scanFilesForServices(dir, discovered);

    return Array.from(discovered.values());
  }

  private scanFilesForServices(dir: string, discovered: Map<string, DiscoveredService>, depth = 0): void {
    if (depth > (this.config.maxDepth || 5)) return;
    if (!existsSync(dir)) return;

    try {
      const entries = readdirSync(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = join(dir, entry.name);

        if (this.config.excludePatterns?.some(p => entry.name.includes(p))) {
          continue;
        }

        if (entry.isDirectory()) {
          this.scanFilesForServices(fullPath, discovered, depth + 1);
        } else if (entry.isFile()) {
          const ext = extname(entry.name).toLowerCase();
          if (EXTENSIONS_TO_SCAN.includes(ext) || entry.name.startsWith('.env')) {
            this.checkFileForServices(fullPath, discovered);
          }
        }
      }
    } catch { /* ignore permission errors */ }
  }

  private checkFileForServices(filePath: string, discovered: Map<string, DiscoveredService>): void {
    try {
      // Skip the scanner's own pattern file to avoid false positives
      if (filePath.includes('local-scanner') || filePath.includes('scanners.ts')) {
        return;
      }

      const stats = statSync(filePath);
      if (stats.size > 1024 * 1024) return; // Skip large files

      const content = readFileSync(filePath, 'utf-8');

      for (const pattern of SERVICE_PATTERNS) {
        if (discovered.has(pattern.id)) continue; // Already found

        for (const regex of pattern.patterns) {
          regex.lastIndex = 0;
          const match = regex.exec(content);
          if (match) {
            discovered.set(pattern.id, {
              id: pattern.id,
              name: pattern.name,
              type: pattern.type,
              source: filePath,
              connectionInfo: this.maskConnectionString(match[0]),
              severity: pattern.severity
            });
            break;
          }
        }
      }
    } catch { /* ignore */ }
  }

  private maskConnectionString(str: string): string {
    // Mask passwords and secrets in connection strings
    return str
      .replace(/:\/\/[^:]+:[^@]+@/, '://***:***@')
      .replace(/password[=:][^&\s]+/gi, 'password=***')
      .replace(/secret[=:][^&\s]+/gi, 'secret=***');
  }

  // Discover code modules/directories in the codebase
  private discoverModules(dir: string): DiscoveredModule[] {
    const modules: DiscoveredModule[] = [];

    // Common module directory patterns and their types
    const MODULE_PATTERNS: Array<{
      pattern: RegExp;
      type: DiscoveredModule['type'];
      name?: string;
    }> = [
      { pattern: /^src$/i, type: 'source', name: 'Source' },
      { pattern: /^(components?|ui)$/i, type: 'component', name: 'Components' },
      { pattern: /^(services?|core)$/i, type: 'service', name: 'Services' },
      { pattern: /^(api|routes?|endpoints?|controllers?)$/i, type: 'api', name: 'API' },
      { pattern: /^(lib|utils?|helpers?|common)$/i, type: 'lib', name: 'Library' },
      { pattern: /^(config|settings?)$/i, type: 'config', name: 'Config' },
      { pattern: /^(tests?|__tests__|spec)$/i, type: 'test', name: 'Tests' },
      { pattern: /^(infra|infrastructure|deploy|k8s|terraform)$/i, type: 'infra', name: 'Infrastructure' },
      { pattern: /^(docs?|documentation)$/i, type: 'docs', name: 'Documentation' },
      { pattern: /^(models?|entities|schemas?)$/i, type: 'source', name: 'Models' },
      { pattern: /^(middleware|interceptors?)$/i, type: 'service', name: 'Middleware' },
      { pattern: /^(hooks|composables)$/i, type: 'component', name: 'Hooks' },
      { pattern: /^(store|state|redux|contexts?)$/i, type: 'service', name: 'State' },
      { pattern: /^(pages?|views?|screens?)$/i, type: 'component', name: 'Pages' },
      { pattern: /^(assets|public|static)$/i, type: 'docs', name: 'Assets' },
      { pattern: /^(types?|interfaces|dtos?)$/i, type: 'source', name: 'Types' },
    ];

    try {
      const entries = readdirSync(dir, { withFileTypes: true });

      for (const entry of entries) {
        if (!entry.isDirectory()) continue;

        // Skip excluded directories
        if (this.config.excludePatterns?.some(p => entry.name.includes(p))) {
          continue;
        }

        const fullPath = join(dir, entry.name);

        // Check if this matches a known module pattern
        for (const mp of MODULE_PATTERNS) {
          if (mp.pattern.test(entry.name)) {
            const moduleInfo = this.analyzeModule(fullPath, entry.name, mp.type, mp.name);
            if (moduleInfo.fileCount > 0) {
              modules.push(moduleInfo);
            }
            break;
          }
        }

        // Also check one level deeper for nested module structures (e.g., src/components)
        if (entry.name === 'src' || entry.name === 'app' || entry.name === 'packages') {
          const nestedModules = this.scanNestedModules(fullPath, MODULE_PATTERNS);
          modules.push(...nestedModules);
        }
      }

      // If we found an src module, also scan it for submodules
      const srcModule = modules.find(m => m.id === 'src');
      if (!srcModule) {
        // If there's no src directory, treat root level as source
        const rootFiles = this.getCodeFiles(dir);
        if (rootFiles.length > 0) {
          modules.push({
            id: 'root',
            name: 'Root',
            path: dir,
            type: 'source',
            fileCount: rootFiles.length,
            files: rootFiles.slice(0, 10), // Limit to first 10
            imports: [],
            exports: []
          });
        }
      }

    } catch { /* ignore permission errors */ }

    return modules;
  }

  private scanNestedModules(
    dir: string,
    patterns: Array<{ pattern: RegExp; type: DiscoveredModule['type']; name?: string }>
  ): DiscoveredModule[] {
    const modules: DiscoveredModule[] = [];

    try {
      const entries = readdirSync(dir, { withFileTypes: true });

      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        if (this.config.excludePatterns?.some(p => entry.name.includes(p))) continue;

        const fullPath = join(dir, entry.name);

        for (const mp of patterns) {
          if (mp.pattern.test(entry.name)) {
            const moduleInfo = this.analyzeModule(fullPath, entry.name, mp.type, mp.name);
            if (moduleInfo.fileCount > 0) {
              modules.push(moduleInfo);
            }
            break;
          }
        }
      }
    } catch { /* ignore */ }

    return modules;
  }

  private analyzeModule(
    dir: string,
    dirName: string,
    type: DiscoveredModule['type'],
    displayName?: string
  ): DiscoveredModule {
    const files = this.getCodeFiles(dir);
    const imports = new Set<string>();
    const exports = new Set<string>();

    // Analyze a sample of files for imports/exports
    const sampleFiles = files.slice(0, 5);
    for (const file of sampleFiles) {
      try {
        const content = readFileSync(join(dir, file), 'utf-8');

        // Extract imports (basic regex for common patterns)
        const importMatches = content.matchAll(/import\s+.*?from\s+['"]([^'"]+)['"]/g);
        for (const match of importMatches) {
          const importPath = match[1];
          // Only track relative imports to other modules
          if (importPath.startsWith('.') || importPath.startsWith('@/')) {
            const moduleName = importPath.split('/')[1] || importPath.split('/')[0];
            if (moduleName && !moduleName.startsWith('.')) {
              imports.add(moduleName.replace('@/', ''));
            }
          }
        }

        // Extract exports (basic regex)
        const exportMatches = content.matchAll(/export\s+(const|function|class|interface|type|default)\s+(\w+)/g);
        for (const match of exportMatches) {
          exports.add(match[2]);
        }
      } catch { /* ignore */ }
    }

    return {
      id: dirName.toLowerCase(),
      name: displayName || dirName.charAt(0).toUpperCase() + dirName.slice(1),
      path: dir,
      type,
      fileCount: files.length,
      files: files.slice(0, 10), // Limit file list
      imports: Array.from(imports).slice(0, 10),
      exports: Array.from(exports).slice(0, 10)
    };
  }

  private getCodeFiles(dir: string, depth = 0): string[] {
    const files: string[] = [];
    if (depth > 3) return files; // Limit recursion

    try {
      const entries = readdirSync(dir, { withFileTypes: true });

      for (const entry of entries) {
        if (this.config.excludePatterns?.some(p => entry.name.includes(p))) continue;

        if (entry.isFile()) {
          const ext = extname(entry.name).toLowerCase();
          if (['.ts', '.tsx', '.js', '.jsx', '.vue', '.svelte', '.py', '.go', '.rs', '.java', '.cs'].includes(ext)) {
            files.push(entry.name);
          }
        } else if (entry.isDirectory() && depth < 3) {
          const subFiles = this.getCodeFiles(join(dir, entry.name), depth + 1);
          files.push(...subFiles.map(f => join(entry.name, f)));
        }
      }
    } catch { /* ignore */ }

    return files;
  }

  private getSystemInfo(): SystemInfo {
    return {
      platform: process.platform,
      hostname: process.env.COMPUTERNAME || process.env.HOSTNAME || 'unknown',
      user: process.env.USERNAME || process.env.USER || 'unknown',
      nodeVersion: process.version,
      cwd: process.cwd()
    };
  }

  private scanForSecrets(dir: string, depth = 0): SecretFinding[] {
    const findings: SecretFinding[] = [];

    if (depth > (this.config.maxDepth || 5)) return findings;
    if (!existsSync(dir)) return findings;

    try {
      const entries = readdirSync(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = join(dir, entry.name);

        // Skip excluded patterns
        if (this.config.excludePatterns?.some(p => entry.name.includes(p))) {
          continue;
        }

        if (entry.isDirectory()) {
          findings.push(...this.scanForSecrets(fullPath, depth + 1));
        } else if (entry.isFile()) {
          // Check if file should be scanned
          const ext = extname(entry.name).toLowerCase();
          const shouldScan = FILES_TO_SCAN.includes(entry.name) ||
                            EXTENSIONS_TO_SCAN.includes(ext);

          if (shouldScan) {
            findings.push(...this.scanFile(fullPath));
          }
        }
      }
    } catch {
      // Ignore permission errors
    }

    return findings;
  }

  private scanFile(filePath: string): SecretFinding[] {
    const findings: SecretFinding[] = [];

    try {
      // Skip test/example/sample files to reduce false positives
      const fileName = basename(filePath);
      if (SKIP_SECRET_SCAN_PATTERNS.some(pattern => pattern.test(fileName) || pattern.test(filePath))) {
        return findings;
      }

      // Skip the scanner's own files
      if (filePath.includes('local-scanner') || filePath.includes('scanners.ts') || filePath.includes('pipeline')) {
        return findings;
      }

      const stats = statSync(filePath);
      // Skip large files (> 1MB)
      if (stats.size > 1024 * 1024) return findings;

      const content = readFileSync(filePath, 'utf-8');
      const lines = content.split('\n');

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        for (const pattern of SECRET_PATTERNS) {
          pattern.regex.lastIndex = 0;
          const match = pattern.regex.exec(line);

          if (match) {
            findings.push({
              file: filePath,
              line: i + 1,
              type: pattern.name,
              snippet: this.maskSecret(line.trim()),
              severity: pattern.severity
            });
          }
        }
      }
    } catch {
      // Ignore read errors
    }

    return findings;
  }

  private maskSecret(text: string): string {
    // Mask secrets in the snippet to avoid exposing them
    return text.replace(/(['"])[^'"]{8,}(['"])/g, '$1***MASKED***$2');
  }

  private async scanPackages(dir: string): Promise<PackageFinding[]> {
    const findings: PackageFinding[] = [];
    const packageJsonPath = join(dir, 'package.json');

    if (!existsSync(packageJsonPath)) return findings;

    try {
      // Try to run npm audit
      const auditOutput = execSync('npm audit --json 2>/dev/null || echo "{}"', {
        cwd: dir,
        encoding: 'utf-8',
        timeout: 30000
      });

      const auditData = JSON.parse(auditOutput);
      const vulnerabilities = auditData.vulnerabilities || {};

      for (const [pkgName, vuln] of Object.entries(vulnerabilities)) {
        const v = vuln as Record<string, unknown>;
        findings.push({
          name: pkgName,
          version: (v.range as string) || 'unknown',
          vulnerabilities: 1,
          severity: this.normalizeSeverity((v.severity as string) || 'medium')
        });
      }
    } catch {
      // npm audit failed, try to read package.json for outdated packages
      try {
        const pkg = JSON.parse(readFileSync(packageJsonPath, 'utf-8'));
        const deps = { ...pkg.dependencies, ...pkg.devDependencies };

        for (const [name, version] of Object.entries(deps)) {
          // Flag very old or pinned versions as potential issues
          if (typeof version === 'string' && !version.startsWith('^') && !version.startsWith('~')) {
            findings.push({
              name,
              version: version as string,
              vulnerabilities: 0,
              severity: 'low'
            });
          }
        }
      } catch {
        // Ignore
      }
    }

    return findings;
  }

  private normalizeSeverity(sev: string): 'critical' | 'high' | 'medium' | 'low' {
    const s = sev.toLowerCase();
    if (s === 'critical' || s === 'crit') return 'critical';
    if (s === 'high' || s === 'h') return 'high';
    if (s === 'medium' || s === 'med' || s === 'moderate') return 'medium';
    return 'low';
  }

  private getGitInfo(dir: string): GitInfo | null {
    const gitDir = join(dir, '.git');
    if (!existsSync(gitDir)) return null;

    try {
      const branch = execSync('git branch --show-current', { cwd: dir, encoding: 'utf-8' }).trim();
      let remoteUrl: string | undefined;
      let uncommittedChanges = 0;
      let lastCommit: string | undefined;

      try {
        remoteUrl = execSync('git remote get-url origin', { cwd: dir, encoding: 'utf-8' }).trim();
      } catch { /* no remote */ }

      try {
        const status = execSync('git status --porcelain', { cwd: dir, encoding: 'utf-8' });
        uncommittedChanges = status.split('\n').filter(l => l.trim()).length;
      } catch { /* ignore */ }

      try {
        lastCommit = execSync('git log -1 --format="%H %s"', { cwd: dir, encoding: 'utf-8' }).trim();
      } catch { /* ignore */ }

      return { branch, remoteUrl, uncommittedChanges, lastCommit };
    } catch {
      return null;
    }
  }

  private scanEnvFiles(dir: string): EnvFileFinding[] {
    const findings: EnvFileFinding[] = [];
    const envFiles = ['.env', '.env.local', '.env.development', '.env.production', '.env.example'];

    for (const envFile of envFiles) {
      const filePath = join(dir, envFile);
      if (!existsSync(filePath)) continue;

      try {
        const content = readFileSync(filePath, 'utf-8');
        const lines = content.split('\n');
        const variables: string[] = [];
        let hasSecrets = false;

        for (const line of lines) {
          if (line.startsWith('#') || !line.includes('=')) continue;

          const [key] = line.split('=');
          if (key) {
            variables.push(key.trim());

            // Check if variable name suggests a secret
            const keyLower = key.toLowerCase();
            if (keyLower.includes('secret') || keyLower.includes('password') ||
                keyLower.includes('key') || keyLower.includes('token') ||
                keyLower.includes('credential')) {
              hasSecrets = true;
            }
          }
        }

        findings.push({
          file: envFile,
          variables,
          hasSecrets
        });
      } catch {
        // Ignore
      }
    }

    return findings;
  }

  // Convert scan result to AuditorInput for visualization
  toAuditorInput(result: LocalScanResult): AuditorInput {
    const filesChanged = [
      ...result.secrets.map(s => s.file),
      ...result.envFiles.map(e => e.file),
      ...result.sastFindings.map(s => s.file)
    ];

    // Build diff from all findings
    const diffParts: string[] = [];

    // Secrets
    for (const s of result.secrets) {
      diffParts.push(`+[SECRET:${s.type}] ${s.file}:${s.line} - ${s.snippet}`);
    }

    // Package vulnerabilities
    for (const p of result.packages) {
      diffParts.push(`+[VULN:${p.severity.toUpperCase()}] ${p.name}@${p.version} - ${p.title || p.vulnId || 'vulnerability found'}`);
    }

    // SAST findings
    for (const s of result.sastFindings) {
      diffParts.push(`+[SAST:${s.severity}] ${s.file}:${s.line} - ${s.rule}: ${s.message}`);
    }

    const changeEvent: ChangeEvent = {
      id: `local-scan-${Date.now()}`,
      type: 'pull_request',
      environment: 'dev',
      repo: result.path,
      commit: result.gitInfo?.lastCommit?.split(' ')[0] || 'local',
      files_changed: [...new Set(filesChanged)],
      diff: diffParts.join('\n')
    };

    // Count SAST severity (normalize from semgrep format)
    const normalizeSastSeverity = (sev: string): 'critical' | 'high' | 'medium' | 'low' => {
      const s = sev?.toLowerCase() || '';
      if (s === 'error' || s === 'critical') return 'critical';
      if (s === 'warning' || s === 'high') return 'high';
      if (s === 'info' || s === 'medium') return 'medium';
      return 'low';
    };

    const vulnSummary = {
      critical: result.secrets.filter(s => s.severity === 'critical').length +
                result.packages.filter(p => p.severity === 'critical').length +
                result.sastFindings.filter(s => normalizeSastSeverity(s.severity) === 'critical').length,
      high: result.secrets.filter(s => s.severity === 'high').length +
            result.packages.filter(p => p.severity === 'high').length +
            result.sastFindings.filter(s => normalizeSastSeverity(s.severity) === 'high').length,
      medium: result.secrets.filter(s => s.severity === 'medium').length +
              result.packages.filter(p => p.severity === 'medium').length +
              result.sastFindings.filter(s => normalizeSastSeverity(s.severity) === 'medium').length,
      low: result.secrets.filter(s => s.severity === 'low').length +
           result.packages.filter(p => p.severity === 'low').length +
           result.sastFindings.filter(s => normalizeSastSeverity(s.severity) === 'low').length
    };

    const evidenceBundle: EvidenceBundle = {
      vuln_scan: `critical: ${vulnSummary.critical}\nhigh: ${vulnSummary.high}\nmedium: ${vulnSummary.medium}\nlow: ${vulnSummary.low}`,
      sbom: result.packages.length > 0
        ? `Packages scanned: ${result.packages.length}\nVulnerable: ${result.packages.filter(p => p.vulnerabilities > 0).length}`
        : undefined,
      sast_results: result.sastFindings.length > 0
        ? `SAST findings: ${result.sastFindings.length}\nTools: ${result.toolsUsed.join(', ')}`
        : undefined
    };

    const criticalAssets: string[] = [];
    if (result.secrets.some(s => s.type.toLowerCase().includes('aws'))) criticalAssets.push('infra');
    if (result.secrets.some(s => s.type.toLowerCase().includes('password'))) criticalAssets.push('auth');
    if (result.secrets.some(s => s.type.toLowerCase().includes('database') || s.type.toLowerCase().includes('connection'))) criticalAssets.push('database');
    if (result.envFiles.some(e => e.hasSecrets)) criticalAssets.push('secrets');
    if (result.sastFindings.some(s => s.rule.toLowerCase().includes('sql') || s.rule.toLowerCase().includes('injection'))) criticalAssets.push('database');
    if (result.sastFindings.some(s => s.rule.toLowerCase().includes('xss') || s.rule.toLowerCase().includes('csrf'))) criticalAssets.push('api');

    return {
      change_event: changeEvent,
      evidence_bundle: evidenceBundle,
      policy_context: {
        critical_assets: criticalAssets.length > 0 ? criticalAssets : ['secrets'],
        risk_tolerance: 'low'
      }
    };
  }
}

// Quick scan function for CLI/API use
export async function quickLocalScan(targetPath: string): Promise<LocalScanResult> {
  const scanner = new LocalScanner({ targetPath });
  return scanner.scan();
}
