// SLOP Server - Minimal implementation for auditor pipeline
// Exposes /tools, /memory, /info endpoints

import { createServer, IncomingMessage, ServerResponse } from 'http';

export interface SlopTool {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
  handler: (args: Record<string, unknown>) => Promise<unknown>;
}

export interface SlopServerConfig {
  port: number;
  host?: string;
}

export class SlopServer {
  private server: ReturnType<typeof createServer> | null = null;
  private tools = new Map<string, SlopTool>();
  private memory = new Map<string, unknown>();
  private config: Required<SlopServerConfig>;

  constructor(config: SlopServerConfig) {
    this.config = {
      port: config.port,
      host: config.host ?? '127.0.0.1'
    };
  }

  registerTool(tool: SlopTool): void {
    this.tools.set(tool.name, tool);
  }

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://${req.headers.host}`);
    const path = url.pathname;

    // CORS headers for visualizer access
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Content-Type', 'application/json');

    // Handle preflight
    if (req.method === 'OPTIONS') {
      res.statusCode = 204;
      res.end();
      return;
    }

    try {
      if (path === '/info' && req.method === 'GET') {
        await this.handleInfo(res);
      } else if (path === '/tools' && req.method === 'GET') {
        await this.handleListTools(res);
      } else if (path === '/tools' && req.method === 'POST') {
        await this.handleCallTool(req, res);
      } else if (path === '/memory' && req.method === 'POST') {
        await this.handleMemoryWrite(req, res);
      } else if (path === '/memory' && req.method === 'GET') {
        await this.handleMemoryRead(url, res);
      } else {
        res.statusCode = 404;
        res.end(JSON.stringify({ error: 'Not found' }));
      }
    } catch (err) {
      // Fail-closed: return 500 on any error
      res.statusCode = 500;
      res.end(JSON.stringify({
        error: 'Internal server error',
        blocked: true
      }));
    }
  }

  private async handleInfo(res: ServerResponse): Promise<void> {
    res.statusCode = 200;
    res.end(JSON.stringify({
      name: 'slop-auditor',
      version: '0.1.0',
      endpoints: ['/info', '/tools', '/memory'],
      tools: Array.from(this.tools.keys())
    }));
  }

  private async handleListTools(res: ServerResponse): Promise<void> {
    const toolList = Array.from(this.tools.values()).map(t => ({
      name: t.name,
      description: t.description,
      parameters: t.parameters
    }));

    res.statusCode = 200;
    res.end(JSON.stringify({ tools: toolList }));
  }

  private async handleCallTool(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await this.readBody(req);
    const { tool, arguments: args } = JSON.parse(body);

    const toolDef = this.tools.get(tool);
    if (!toolDef) {
      res.statusCode = 404;
      res.end(JSON.stringify({ error: `Tool not found: ${tool}` }));
      return;
    }

    const result = await toolDef.handler(args ?? {});
    res.statusCode = 200;
    res.end(JSON.stringify({ result }));
  }

  private async handleMemoryWrite(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await this.readBody(req);
    const { key, value, metadata } = JSON.parse(body);

    this.memory.set(key, { value, metadata, timestamp: new Date().toISOString() });

    res.statusCode = 201;
    res.end(JSON.stringify({ status: 'stored', key }));
  }

  private async handleMemoryRead(url: URL, res: ServerResponse): Promise<void> {
    const key = url.searchParams.get('key');

    if (key) {
      const entry = this.memory.get(key);
      if (entry) {
        res.statusCode = 200;
        res.end(JSON.stringify(entry));
      } else {
        res.statusCode = 404;
        res.end(JSON.stringify({ error: 'Key not found' }));
      }
    } else {
      res.statusCode = 200;
      res.end(JSON.stringify({ keys: Array.from(this.memory.keys()) }));
    }
  }

  private readBody(req: IncomingMessage): Promise<string> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      req.on('data', chunk => chunks.push(chunk));
      req.on('end', () => resolve(Buffer.concat(chunks).toString()));
      req.on('error', reject);
    });
  }

  async start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server = createServer((req, res) => {
        this.handleRequest(req, res).catch(() => {
          res.statusCode = 500;
          res.end(JSON.stringify({ error: 'Internal error', blocked: true }));
        });
      });

      this.server.on('error', reject);
      this.server.listen(this.config.port, this.config.host, () => {
        resolve();
      });
    });
  }

  async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }

  getMemorySnapshot(): Map<string, unknown> {
    return new Map(this.memory);
  }
}
