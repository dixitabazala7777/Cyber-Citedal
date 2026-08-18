export interface Incident {
  id: string;
  timestamp: string; // ISO string or format
  sourceIp: string;
  targetService: string;
  category: 'DDoS' | 'SQL Injection' | 'Phishing' | 'Brute Force' | 'Port Scan' | 'Malware';
  severity: 'critical' | 'high' | 'medium' | 'info';
  status: 'active' | 'blocked' | 'monitored' | 'investigating' | 'resolved';
  countryCode: string;
  payload?: string;
}

export interface SystemNode {
  id: string;
  name: string;
  region: string;
  status: 'operational' | 'degraded' | 'offline' | 'isolated';
  cpuUsage: number;
  memoryUsage: number;
  latency: number;
}

export interface FirewallRule {
  id: string;
  ipRange: string;
  description: string;
  action: 'block' | 'bypass' | 'challenge';
  createdBy: string;
  createdAt: string;
  isActive: boolean;
}

export interface ChartDataPoint {
  time: string;
  traffic: number;
  threats: number;
  blocked: number;
}
