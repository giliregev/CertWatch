/**
 * CertWatch - Server
 * Handles scan requests, runs PowerShell, streams results via WebSocket
 */

const express   = require('express');
const http      = require('http');
const { WebSocketServer } = require('ws');
const { spawn } = require('child_process');
const path      = require('path');
const fs        = require('fs');

const app    = express();
const server = http.createServer(app);
const wss    = new WebSocketServer({ server });

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Active scans ────────────────────────────────────────
let activeScans = {};  // scanId -> { ps, cancelled }

// ─── WebSocket broadcast ─────────────────────────────────
function broadcast(ws, data) {
  if (ws.readyState === 1) ws.send(JSON.stringify(data));
}

// ─── Parse IP range ──────────────────────────────────────
function parseIPRange(rangeStr) {
  const ips = [];
  rangeStr = rangeStr.trim();

  // 192.168.1.1-254
  const rangeMatch = rangeStr.match(/^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$/);
  if (rangeMatch) {
    const prefix = rangeMatch[1];
    const start  = parseInt(rangeMatch[2]);
    const end    = parseInt(rangeMatch[3]);
    for (let i = start; i <= end; i++) ips.push(`${prefix}${i}`);
    return ips;
  }

  // CIDR 192.168.1.0/24
  const cidrMatch = rangeStr.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
  if (cidrMatch) {
    const ipParts = cidrMatch[1].split('.').map(Number);
    const bits    = parseInt(cidrMatch[2]);
    const ipInt   = (ipParts[0]<<24)|(ipParts[1]<<16)|(ipParts[2]<<8)|ipParts[3];
    const mask    = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    const network = (ipInt & mask) >>> 0;
    const count   = (~mask >>> 0) - 1;
    for (let i = 1; i <= count; i++) {
      const h = (network + i) >>> 0;
      ips.push([(h>>>24)&255,(h>>>16)&255,(h>>>8)&255,h&255].join('.'));
    }
    return ips;
  }

  // comma list
  if (rangeStr.includes(',')) return rangeStr.split(',').map(s => s.trim());

  // single IP
  return [rangeStr];
}

// ─── PowerShell runner ───────────────────────────────────
function runPS(script) {
  return new Promise((resolve, reject) => {
    const ps = spawn('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
      '-Command', script
    ]);
    let out = '', err = '';
    ps.stdout.on('data', d => out += d.toString());
    ps.stderr.on('data', d => err += d.toString());
    ps.on('close', code => {
      if (code !== 0 && err) reject(new Error(err.trim()));
      else resolve(out.trim());
    });
  });
}

// ─── Ping an IP ──────────────────────────────────────────
async function pingIP(ip, timeoutSec) {
  try {
    const result = await runPS(
      `$p = New-Object System.Net.NetworkInformation.Ping; ` +
      `$r = $p.Send('${ip}', ${timeoutSec * 1000}); ` +
      `if ($r.Status -eq 'Success') { Write-Output 'alive' } else { Write-Output 'dead' }`
    );
    return result.includes('alive');
  } catch { return false; }
}

// ─── Resolve hostname ────────────────────────────────────
async function resolveHostname(ip) {
  try {
    const result = await runPS(
      `try { ([System.Net.Dns]::GetHostEntry('${ip}').HostName -split '\\.')[0] } catch { '${ip}' }`
    );
    return result || ip;
  } catch { return ip; }
}

// ─── Get certs from remote machine ───────────────────────
async function getCerts(ip, useCurrentUser, username, password) {
  const certScript = `
    $certs = Get-ChildItem -Path Cert:\\LocalMachine\\My -ErrorAction SilentlyContinue
    $result = $certs | ForEach-Object {
      [PSCustomObject]@{
        Subject      = $_.Subject
        Issuer       = $_.Issuer
        NotAfter     = $_.NotAfter.ToString('yyyy-MM-dd')
        DaysLeft     = [int]($_.NotAfter - (Get-Date)).TotalDays
        FriendlyName = $_.FriendlyName
        Thumbprint   = $_.Thumbprint
      }
    }
    if ($result) { $result | ConvertTo-Json -Compress }
    else { '[]' }
  `;

  let invokeCmd;
  if (useCurrentUser) {
    invokeCmd = `Invoke-Command -ComputerName '${ip}' -ScriptBlock { ${certScript} } -ErrorAction Stop`;
  } else {
    const escapedPass = password.replace(/'/g, "''");
    invokeCmd = `
      $sp   = ConvertTo-SecureString '${escapedPass}' -AsPlainText -Force
      $cred = New-Object PSCredential('${username}', $sp)
      Invoke-Command -ComputerName '${ip}' -Credential $cred -ScriptBlock { ${certScript} } -ErrorAction Stop
    `;
  }

  try {
    const raw = await runPS(invokeCmd);
    if (!raw || raw === 'null') return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch (e) {
    return { error: e.message };
  }
}

// ─── Scan endpoint ───────────────────────────────────────
wss.on('connection', (ws) => {
  ws.on('message', async (msg) => {
    let req;
    try { req = JSON.parse(msg); } catch { return; }

    if (req.type === 'start_scan') {
      const {
        ipRange, timeoutSec = 1, threads = 30,
        useCurrentUser = true, username = '', password = '',
        critDays = 30, warnDays = 60, noticeDays = 90
      } = req;

      let ips;
      try {
        ips = parseIPRange(ipRange);
      } catch (e) {
        return broadcast(ws, { type: 'error', message: `Invalid IP range: ${e.message}` });
      }

      broadcast(ws, { type: 'scan_started', total: ips.length });

      const scanId  = Date.now().toString();
      activeScans[scanId] = { cancelled: false };

      let done = 0;
      const BATCH = Math.min(threads, 20); // process in batches

      for (let i = 0; i < ips.length; i += BATCH) {
        if (activeScans[scanId]?.cancelled) break;

        const batch = ips.slice(i, i + BATCH);
        await Promise.all(batch.map(async (ip) => {
          if (activeScans[scanId]?.cancelled) return;

          // ping
          const alive = await pingIP(ip, timeoutSec);
          done++;

          if (!alive) {
            broadcast(ws, { type: 'progress', done, total: ips.length, ip, alive: false });
            return;
          }

          // hostname
          const hostname = await resolveHostname(ip);

          // certs
          const certsResult = await getCerts(ip, useCurrentUser, username, password);
          const winrmError  = certsResult?.error || null;
          const certs       = winrmError ? [] : certsResult;

          // tag each cert
          const taggedCerts = certs.map(c => {
            let status, color;
            if      (c.DaysLeft < 0)          { status = 'Expired';  color = 'expired';  }
            else if (c.DaysLeft <= critDays)   { status = 'Critical'; color = 'critical'; }
            else if (c.DaysLeft <= warnDays)   { status = 'Warning';  color = 'warning';  }
            else if (c.DaysLeft <= noticeDays) { status = 'Notice';   color = 'notice';   }
            else                              { status = 'OK';       color = 'ok';       }
            return { ...c, status, color };
          });

          broadcast(ws, {
            type: 'host_result',
            ip, hostname, alive: true,
            certs: taggedCerts,
            winrmError,
            done,
            total: ips.length
          });
        }));
      }

      delete activeScans[scanId];
      broadcast(ws, { type: 'scan_complete' });
    }

    if (req.type === 'stop_scan') {
      Object.keys(activeScans).forEach(id => activeScans[id].cancelled = true);
      broadcast(ws, { type: 'scan_stopped' });
    }
  });
});

// ─── Start server ─────────────────────────────────────────
const PORT = 3000;
server.listen(PORT, '127.0.0.1', () => {
  console.log('');
  console.log('  ╔══════════════════════════════════════╗');
  console.log('  ║   CertWatch is running               ║');
  console.log('  ║   Open: http://localhost:3000        ║');
  console.log('  ║   Press Ctrl+C to stop               ║');
  console.log('  ╚══════════════════════════════════════╝');
  console.log('');
  // auto-open browser
  spawn('cmd.exe', ['/c', 'start', `http://localhost:${PORT}`], { detached: true, stdio: 'ignore' });
});
