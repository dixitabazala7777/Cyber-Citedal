import { Incident, SystemNode, FirewallRule, ChartDataPoint } from '../types';

// Helper to generate IDs
const generateId = () => Math.random().toString(36).substring(2, 11).toUpperCase();

// Helper to get formatted time
export const getFormattedTime = (date: Date = new Date()) => {
  return date.toLocaleTimeString('en-US', { hour12: false });
};

// Past 20 hours chart data
export const generateInitialChartData = (): ChartDataPoint[] => {
  const data: ChartDataPoint[] = [];
  const now = new Date();
  for (let i = 19; i >= 0; i--) {
    const timePoint = new Date(now.getTime() - i * 60 * 60 * 1000);
    data.push({
      time: timePoint.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false }),
      traffic: Math.floor(Math.random() * 200) + 300,
      threats: Math.floor(Math.random() * 15) + 2,
      blocked: Math.floor(Math.random() * 10) + 1,
    });
  }
  return data;
};

// Initial nodes
export const initialNodes: SystemNode[] = [
  {
    id: 'NODE-US-EAST',
    name: 'US-EAST-01 (Primary Gateway)',
    region: 'N. Virginia, USA',
    status: 'operational',
    cpuUsage: 42,
    memoryUsage: 56,
    latency: 28,
  },
  {
    id: 'NODE-EU-WEST',
    name: 'EU-WEST-02 (Core Compute)',
    region: 'Dublin, Ireland',
    status: 'operational',
    cpuUsage: 28,
    memoryUsage: 44,
    latency: 82,
  },
  {
    id: 'NODE-AP-SOUTH',
    name: 'AP-SOUTH-01 (Edge Proxy)',
    region: 'Mumbai, India',
    status: 'operational',
    cpuUsage: 61,
    memoryUsage: 72,
    latency: 145,
  },
  {
    id: 'NODE-US-WEST',
    name: 'US-WEST-02 (Secure Vault)',
    region: 'Oregon, USA',
    status: 'operational',
    cpuUsage: 19,
    memoryUsage: 35,
    latency: 52,
  },
  {
    id: 'NODE-SA-EAST',
    name: 'SA-EAST-01 (Database Mirror)',
    region: 'São Paulo, Brazil',
    status: 'degraded',
    cpuUsage: 86,
    memoryUsage: 91,
    latency: 210,
  }
];

// IP addresses for mock threats
const mockIps = [
  '185.220.101.4',
  '45.143.203.18',
  '103.209.24.112',
  '91.241.19.84',
  '198.51.100.72',
  '203.0.113.15',
  '82.102.23.41',
  '194.26.135.5'
];

const targetServices = [
  '/api/v1/auth/login',
  '/api/v1/transactions/execute',
  'SSH Gateway (Port 22)',
  'Main Database Pool',
  'DNS resolver',
  '/api/v1/user/profile',
  'Kube-API Server'
];

const incidentCategories = [
  { category: 'DDoS' as const, severity: 'critical' as const, payload: 'Volumetric HTTP Flood - 45k req/sec' },
  { category: 'SQL Injection' as const, severity: 'high' as const, payload: "UNION SELECT username, password_hash FROM users --" },
  { category: 'Phishing' as const, severity: 'medium' as const, payload: 'Suspicious email origin referencing invoice-auth.com' },
  { category: 'Brute Force' as const, severity: 'high' as const, payload: '150 failed SSH authentication attempts in 30 seconds' },
  { category: 'Port Scan' as const, severity: 'info' as const, payload: 'Sequential port probing detected on range 1000-5000' },
  { category: 'Malware' as const, severity: 'critical' as const, payload: 'Known trojan signature detected in uploaded invoice attachment' }
];

const countryCodes = ['CN', 'RU', 'US', 'NL', 'UA', 'KP', 'BR', 'IR'];

export const generateRandomIncident = (): Incident => {
  const ip = mockIps[Math.floor(Math.random() * mockIps.length)];
  const service = targetServices[Math.floor(Math.random() * targetServices.length)];
  const catChoice = incidentCategories[Math.floor(Math.random() * incidentCategories.length)];
  const country = countryCodes[Math.floor(Math.random() * countryCodes.length)];
  const id = `INC-${generateId()}`;
  
  return {
    id,
    timestamp: new Date().toISOString(),
    sourceIp: ip,
    targetService: service,
    category: catChoice.category,
    severity: catChoice.severity,
    status: Math.random() > 0.3 ? 'blocked' : 'active',
    countryCode: country,
    payload: catChoice.payload
  };
};

// Build the initial set of incidents
export const generateInitialIncidents = (): Incident[] => {
  const incidents: Incident[] = [];
  const now = new Date();
  
  for (let i = 0; i < 12; i++) {
    const minutesAgo = (i + 1) * 8 + Math.floor(Math.random() * 5);
    const incidentTime = new Date(now.getTime() - minutesAgo * 60 * 1000);
    const mockInc = generateRandomIncident();
    mockInc.timestamp = incidentTime.toISOString();
    // Older incidents are mostly blocked or resolved
    mockInc.status = i > 4 ? 'blocked' : (Math.random() > 0.5 ? 'blocked' : 'active');
    incidents.push(mockInc);
  }
  
  return incidents.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
};

// Initial firewall rules
export const initialFirewallRules: FirewallRule[] = [
  {
    id: 'FW-RULE-001',
    ipRange: '185.220.101.0/24',
    description: 'Block known malicious exit nodes (TOR)',
    action: 'block',
    createdBy: 'sec-ops-bot',
    createdAt: new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString(),
    isActive: true,
  },
  {
    id: 'FW-RULE-002',
    ipRange: '103.209.24.0/22',
    description: 'Enforce MFA / Challenge challenge on AP Edge Proxy block',
    action: 'challenge',
    createdBy: 'admin@shieldpulse.enterprise',
    createdAt: new Date(Date.now() - 12 * 60 * 60 * 1000).toISOString(),
    isActive: true,
  },
  {
    id: 'FW-RULE-003',
    ipRange: '198.51.100.72',
    description: 'Whitelist partner analytics scraper',
    action: 'bypass',
    createdBy: 'devops-lead',
    createdAt: new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString(),
    isActive: true,
  }
];
