'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const {spawn, spawnSync} = require('child_process');

const EXPECTED = Object.freeze({
  markdownIt: '14.3.0',
  mithril: '2.3.8',
  perfettoCommit: '6c2950fee6d95466d66c8ccfcef2c308497c3d99',
  sourcePath: 'ui/src/plugins/com.google.PerfettoMcp/chat_page.ts',
  sourcePathExpression: 'm.trust(MarkdownIt().render(vnode.attrs.message))',
});

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function findPackageRoot(packageName) {
  let current = path.dirname(require.resolve(packageName));
  while (true) {
    const candidate = path.join(current, 'package.json');
    if (fs.existsSync(candidate)) {
      const pkg = JSON.parse(fs.readFileSync(candidate, 'utf8'));
      if (pkg.name === packageName) return current;
    }
    const parent = path.dirname(current);
    if (parent === current) throw new Error(`Unable to locate package root for ${packageName}`);
    current = parent;
  }
}

function findChrome() {
  const candidates = [
    process.env.CHROME_PATH,
    '/usr/bin/google-chrome-stable',
    '/usr/bin/google-chrome',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
  ].filter(Boolean);
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }
  for (const name of ['google-chrome-stable', 'google-chrome', 'chromium', 'chromium-browser']) {
    const resolved = spawnSync('bash', ['-lc', `command -v ${name}`], {encoding: 'utf8'}).stdout.trim();
    if (resolved) return resolved;
  }
  throw new Error('No Chrome/Chromium executable found on the runner');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForFile(filePath, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fs.existsSync(filePath)) return;
    await sleep(50);
  }
  throw new Error(`Timed out waiting for ${filePath}`);
}

async function waitForJson(url, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.ok) return await response.json();
      lastError = new Error(`HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await sleep(100);
  }
  throw new Error(`Timed out reading ${url}: ${lastError}`);
}

class CdpClient {
  constructor(url) {
    this.url = url;
    this.nextId = 1;
    this.pending = new Map();
    this.ws = null;
  }

  async connect() {
    this.ws = new WebSocket(this.url);
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('CDP websocket open timeout')), 10000);
      this.ws.addEventListener('open', () => {
        clearTimeout(timer);
        resolve();
      }, {once: true});
      this.ws.addEventListener('error', (event) => {
        clearTimeout(timer);
        reject(new Error(`CDP websocket error: ${event.message || 'unknown'}`));
      }, {once: true});
    });
    this.ws.addEventListener('message', (event) => {
      const message = JSON.parse(String(event.data));
      if (!message.id) return;
      const entry = this.pending.get(message.id);
      if (!entry) return;
      this.pending.delete(message.id);
      if (message.error) entry.reject(new Error(`${message.error.code}: ${message.error.message}`));
      else entry.resolve(message.result);
    });
    this.ws.addEventListener('close', () => {
      for (const {reject} of this.pending.values()) reject(new Error('CDP websocket closed'));
      this.pending.clear();
    });
  }

  call(method, params = {}) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, {resolve, reject});
      this.ws.send(JSON.stringify({id, method, params}));
    });
  }

  close() {
    if (this.ws) this.ws.close();
  }
}

function makeHarnessScript() {
  return String.raw`
(() => {
  'use strict';
  window.__pocHits = [];
  window.__pocDone = false;
  window.__pocError = null;

  const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const md = window.markdownit();

  const cases = [
    {id: 'raw_img', kind: 'blocked', input: '<img src="/missing-raw.png" onerror="window.__pocHits.push(\'raw_img\')">'},
    {id: 'raw_svg', kind: 'blocked', input: '<svg onload="window.__pocHits.push(\'raw_svg\')"></svg>'},
    {id: 'raw_script', kind: 'blocked', input: '<script>window.__pocHits.push(\'raw_script\')</' + 'script>'},
    {id: 'markdown_javascript', kind: 'blocked', input: '[x](javascript:window.__pocHits.push(\'markdown_javascript\'))'},
    {id: 'mixed_case_javascript', kind: 'blocked', input: '[x](JaVaScRiPt:window.__pocHits.push(\'mixed_case_javascript\'))'},
    {id: 'entity_javascript', kind: 'blocked', input: '[x](java&#x73;cript:window.__pocHits.push(\'entity_javascript\'))'},
    {id: 'percent_newline_javascript', kind: 'blocked', input: '[x](java%0ascript:window.__pocHits.push(\'percent_newline_javascript\'))'},
    {id: 'literal_tab_javascript', kind: 'blocked', input: '[x](java\tscript:window.__pocHits.push(\'literal_tab_javascript\'))'},
    {id: 'vbscript', kind: 'blocked', input: '[x](vbscript:msgbox(1))'},
    {id: 'file_scheme', kind: 'blocked', input: '[x](file:///etc/passwd)'},
    {id: 'data_html', kind: 'blocked', input: '[x](data:text/html,<script>window.__pocHits.push(1)</' + 'script>)'},
    {id: 'data_svg_link', kind: 'blocked', input: '[x](data:image/svg+xml,<svg onload=window.__pocHits.push(1)></svg>)'},
    {id: 'data_svg_image', kind: 'blocked', input: '![x](data:image/svg+xml,<svg onload=window.__pocHits.push(1)></svg>)'},
    {id: 'title_breakout', kind: 'blocked', input: '[x](https://example.test/ "x&quot; onmouseover=&quot;window.__pocHits.push(1)")'},
    {id: 'alt_breakout', kind: 'blocked', input: '![x" onerror="window.__pocHits.push(1)](https://example.test/a.png)'},
    {id: 'autolink_javascript', kind: 'blocked', input: '<javascript:window.__pocHits.push(1)>'},
    {id: 'plaintext_linkify_disabled', kind: 'blocked', input: 'javascript:window.__pocHits.push(1)'},
    {id: 'benign_https', kind: 'benign_link', input: '[safe](https://example.test/path?q=1#ok)'},
    {id: 'benign_mailto', kind: 'benign_link', input: '[mail](mailto:a@example.test)'},
    {id: 'allowed_data_png', kind: 'benign_image', input: '![p](data:image/png;base64,iVBORw0KGgo=)'},
  ];

  function inspect(root, id, rendered) {
    const elements = [...root.querySelectorAll('*')];
    const eventAttributes = [];
    const urlAttributes = [];
    for (const element of elements) {
      for (const attr of [...element.attributes]) {
        if (/^on/i.test(attr.name)) {
          eventAttributes.push({tag: element.tagName, name: attr.name, value: attr.value});
        }
        if (/^(href|src|xlink:href|formaction)$/i.test(attr.name)) {
          urlAttributes.push({tag: element.tagName, name: attr.name, value: attr.value});
        }
      }
    }
    const dangerousUrlAttributes = urlAttributes.filter(({value}) => {
      const compact = String(value).replace(/[\u0000-\u0020\u007f-\u009f]/g, '').toLowerCase();
      if (/^(javascript|vbscript|file):/.test(compact)) return true;
      if (compact.startsWith('data:') && !/^data:image\/(gif|png|jpeg|webp);/i.test(compact)) return true;
      return false;
    });
    return {
      id,
      rendered,
      innerHTML: root.innerHTML,
      textContent: root.textContent,
      tagNames: elements.map((element) => element.tagName),
      eventAttributes,
      urlAttributes,
      dangerousUrlAttributes,
      hits: [...window.__pocHits],
    };
  }

  async function renderDefault(testCase) {
    window.__pocHits.length = 0;
    const root = document.createElement('section');
    root.dataset.case = testCase.id;
    document.body.appendChild(root);
    const rendered = md.render(testCase.input);
    window.m.render(root, window.m.trust(rendered));
    await delay(300);
    const observation = inspect(root, testCase.id, rendered);
    root.remove();
    return observation;
  }

  async function positiveControl(id, rendered) {
    window.__pocHits.length = 0;
    const root = document.createElement('section');
    root.dataset.control = id;
    document.body.appendChild(root);
    window.m.render(root, window.m.trust(rendered));
    await delay(500);
    const observation = inspect(root, id, rendered);
    root.remove();
    return observation;
  }

  (async () => {
    const observations = [];
    const assertions = [];
    for (const testCase of cases) {
      const observation = await renderDefault(testCase);
      observations.push({...testCase, ...observation});

      if (testCase.kind === 'blocked') {
        assertions.push({
          id: testCase.id,
          pass: observation.hits.length === 0
            && observation.eventAttributes.length === 0
            && observation.dangerousUrlAttributes.length === 0,
          criteria: 'no execution, no event-handler attributes, no dangerous URL attributes',
        });
      } else if (testCase.kind === 'benign_link') {
        assertions.push({
          id: testCase.id,
          pass: observation.hits.length === 0
            && observation.eventAttributes.length === 0
            && observation.dangerousUrlAttributes.length === 0
            && observation.tagNames.includes('A')
            && observation.urlAttributes.some((attr) => attr.name.toLowerCase() === 'href'),
          criteria: 'benign link remains functional without executable attributes',
        });
      } else if (testCase.kind === 'benign_image') {
        assertions.push({
          id: testCase.id,
          pass: observation.hits.length === 0
            && observation.eventAttributes.length === 0
            && observation.dangerousUrlAttributes.length === 0
            && observation.tagNames.includes('IMG')
            && observation.urlAttributes.some((attr) => attr.name.toLowerCase() === 'src'),
          criteria: 'allowed raster data image remains functional without executable attributes',
        });
      }
    }

    const directPayload = '<img src="/missing-positive-direct.png" onerror="window.__pocHits.push(\'positive_direct_mtrust\')">';
    const positiveDirect = await positiveControl('positive_direct_mtrust', directPayload);

    const htmlEnabled = window.markdownit({html: true});
    const htmlEnabledSource = '<img src="/missing-positive-html.png" onerror="window.__pocHits.push(\'positive_markdown_html_enabled\')">';
    const positiveHtmlEnabled = await positiveControl(
      'positive_markdown_html_enabled',
      htmlEnabled.render(htmlEnabledSource),
    );

    const positiveAssertions = [
      {
        id: 'positive_direct_mtrust',
        pass: positiveDirect.tagNames.includes('IMG')
          && positiveDirect.eventAttributes.some((attr) => attr.name.toLowerCase() === 'onerror')
          && positiveDirect.hits.includes('positive_direct_mtrust'),
        criteria: 'real Mithril m.trust sink executes an injected image error handler',
      },
      {
        id: 'positive_markdown_html_enabled',
        pass: positiveHtmlEnabled.tagNames.includes('IMG')
          && positiveHtmlEnabled.eventAttributes.some((attr) => attr.name.toLowerCase() === 'onerror')
          && positiveHtmlEnabled.hits.includes('positive_markdown_html_enabled'),
        criteria: 'same parser and sink become exploitable when markdown-it html option is enabled',
      },
    ];

    const allAssertions = [...assertions, ...positiveAssertions];
    window.__pocResults = {
      defaultOptions: {...md.options},
      cases: observations,
      positiveControls: {directMTrust: positiveDirect, markdownHtmlEnabled: positiveHtmlEnabled},
      assertions: allAssertions,
      allAssertionsPass: allAssertions.every((item) => item.pass),
    };
    window.__pocDone = true;
    document.title = 'POC_DONE';
  })().catch((error) => {
    window.__pocError = String(error && error.stack || error);
    window.__pocDone = true;
    document.title = 'POC_ERROR';
  });
})();
`;
}

async function main() {
  const startedAt = new Date().toISOString();
  const markdownRoot = findPackageRoot('markdown-it');
  const mithrilRoot = findPackageRoot('mithril');
  const markdownPackage = JSON.parse(fs.readFileSync(path.join(markdownRoot, 'package.json'), 'utf8'));
  const mithrilPackage = JSON.parse(fs.readFileSync(path.join(mithrilRoot, 'package.json'), 'utf8'));
  assert.strictEqual(markdownPackage.version, EXPECTED.markdownIt, 'unexpected markdown-it version');
  assert.strictEqual(mithrilPackage.version, EXPECTED.mithril, 'unexpected Mithril version');

  const markdownBundlePath = path.join(markdownRoot, 'dist', 'markdown-it.js');
  const mithrilBundlePath = path.join(mithrilRoot, 'mithril.js');
  const markdownBundle = fs.readFileSync(markdownBundlePath);
  const mithrilBundle = fs.readFileSync(mithrilBundlePath);
  const harnessScript = Buffer.from(makeHarnessScript(), 'utf8');
  const packageLock = JSON.parse(fs.readFileSync(path.join(__dirname, 'package-lock.json'), 'utf8'));

  const server = http.createServer((request, response) => {
    if (request.url === '/') {
      response.writeHead(200, {'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store'});
      response.end('<!doctype html><meta charset="utf-8"><title>POC_RUNNING</title><body><script src="/markdown-it.js"></script><script src="/mithril.js"></script><script src="/harness.js"></script>');
      return;
    }
    if (request.url === '/markdown-it.js') {
      response.writeHead(200, {'content-type': 'text/javascript; charset=utf-8', 'cache-control': 'no-store'});
      response.end(markdownBundle);
      return;
    }
    if (request.url === '/mithril.js') {
      response.writeHead(200, {'content-type': 'text/javascript; charset=utf-8', 'cache-control': 'no-store'});
      response.end(mithrilBundle);
      return;
    }
    if (request.url === '/harness.js') {
      response.writeHead(200, {'content-type': 'text/javascript; charset=utf-8', 'cache-control': 'no-store'});
      response.end(harnessScript);
      return;
    }
    response.writeHead(404, {'content-type': 'text/plain'});
    response.end('not found');
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const serverPort = server.address().port;
  const chromePath = findChrome();
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'perfetto-md-poc-'));
  const activePortFile = path.join(userDataDir, 'DevToolsActivePort');
  const chrome = spawn(chromePath, [
    '--headless=new',
    '--no-sandbox',
    '--disable-gpu',
    '--disable-dev-shm-usage',
    '--remote-debugging-port=0',
    '--remote-allow-origins=*',
    `--user-data-dir=${userDataDir}`,
    `http://127.0.0.1:${serverPort}/`,
  ], {stdio: ['ignore', 'pipe', 'pipe']});
  let chromeStderr = '';
  chrome.stderr.on('data', (chunk) => { chromeStderr += chunk.toString(); });

  let cdp;
  let evidence;
  try {
    await waitForFile(activePortFile);
    const [debugPort] = fs.readFileSync(activePortFile, 'utf8').trim().split(/\r?\n/);
    const targets = await waitForJson(`http://127.0.0.1:${debugPort}/json/list`);
    const target = targets.find((item) => item.type === 'page');
    if (!target) throw new Error('No CDP page target found');
    cdp = new CdpClient(target.webSocketDebuggerUrl);
    await cdp.connect();
    await cdp.call('Runtime.enable');
    const browserVersion = await cdp.call('Browser.getVersion');

    const deadline = Date.now() + 30000;
    let browserResults = null;
    let browserError = null;
    while (Date.now() < deadline) {
      const evaluation = await cdp.call('Runtime.evaluate', {
        expression: 'window.__pocDone ? ({results: window.__pocResults || null, error: window.__pocError || null}) : null',
        returnByValue: true,
      });
      const value = evaluation.result && evaluation.result.value;
      if (value) {
        browserResults = value.results;
        browserError = value.error;
        break;
      }
      await sleep(100);
    }
    if (browserError) throw new Error(`Browser harness failed: ${browserError}`);
    if (!browserResults) throw new Error('Browser harness did not finish within 30 seconds');

    const lockPackages = packageLock.packages || {};
    evidence = {
      schemaVersion: 1,
      finding: 'Perfetto MCP chat markdown-it output passed to Mithril m.trust',
      intent: 'runtime disproof of executable markup/URL injection under exact default dependency versions',
      target: EXPECTED,
      timing: {startedAt, finishedAt: new Date().toISOString()},
      environment: {
        node: process.version,
        platform: `${process.platform}/${process.arch}`,
        chromePath,
        browser: browserVersion,
      },
      dependencyEvidence: {
        markdownIt: {
          version: markdownPackage.version,
          bundlePath: path.relative(__dirname, markdownBundlePath),
          bundleSha256: sha256(markdownBundle),
          lockResolved: lockPackages['node_modules/markdown-it'] && lockPackages['node_modules/markdown-it'].resolved,
          lockIntegrity: lockPackages['node_modules/markdown-it'] && lockPackages['node_modules/markdown-it'].integrity,
        },
        mithril: {
          version: mithrilPackage.version,
          bundlePath: path.relative(__dirname, mithrilBundlePath),
          bundleSha256: sha256(mithrilBundle),
          lockResolved: lockPackages['node_modules/mithril'] && lockPackages['node_modules/mithril'].resolved,
          lockIntegrity: lockPackages['node_modules/mithril'] && lockPackages['node_modules/mithril'].integrity,
        },
        harnessSha256: sha256(harnessScript),
        packageLockSha256: sha256(fs.readFileSync(path.join(__dirname, 'package-lock.json'))),
      },
      runtime: browserResults,
      conclusion: {
        technicalStatus: browserResults.allAssertionsPass ? 'REFUTED' : 'NOT_REFUTED',
        readyToSubmit: false,
        reason: browserResults.allAssertionsPass
          ? 'Exact markdown-it default options prevented executable HTML and dangerous URL attributes before the exact Mithril m.trust sink; both positive controls executed in real Chromium.'
          : 'One or more runtime assertions failed; further analysis required.',
      },
    };
    fs.writeFileSync(path.join(__dirname, 'runtime-evidence.json'), `${JSON.stringify(evidence, null, 2)}\n`);
    console.log(`RUNTIME_EVIDENCE_JSON=${JSON.stringify(evidence)}`);
    console.log(`ALL_ASSERTIONS_PASS=${browserResults.allAssertionsPass}`);
    if (!browserResults.allAssertionsPass) process.exitCode = 1;
  } finally {
    if (cdp) cdp.close();
    chrome.kill('SIGTERM');
    server.close();
    await sleep(200);
    fs.rmSync(userDataDir, {recursive: true, force: true});
    if (chromeStderr) fs.writeFileSync(path.join(__dirname, 'chrome-stderr.log'), chromeStderr);
  }
}

main().catch((error) => {
  const failure = {
    schemaVersion: 1,
    target: EXPECTED,
    technicalStatus: 'HARNESS_ERROR',
    error: String(error && error.stack || error),
    timestamp: new Date().toISOString(),
  };
  fs.writeFileSync(path.join(__dirname, 'runtime-evidence.json'), `${JSON.stringify(failure, null, 2)}\n`);
  console.error(`RUNTIME_HARNESS_ERROR=${JSON.stringify(failure)}`);
  process.exitCode = 1;
});
