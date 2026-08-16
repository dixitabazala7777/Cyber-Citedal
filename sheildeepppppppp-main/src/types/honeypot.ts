export interface AttackerGeo {
  ip: string;
  country: string;
  countryCode: string;
  hitCount: number;
  lastActive: string;
}

export interface HoneypotSensor {
  id: string;
  name: string;
  serviceType: 'Cowrie' | 'Dionaea' | 'ElasticPot' | 'Conpot';
  status: 'operational' | 'degraded' | 'offline';
  cpu: number;
  memory: number;
  hitCount: number;
  port: number;
}

export interface ActiveBlocklistRule {
  id: string;
  ip: string;
  bannedAt: string;
  reason: string;
  duration: string;
}

export interface HoneypotAnalytics {
  topTargetedPorts: { name: string; hits: number }[];
  attackerGeoStats: { name: string; hits: number }[];
  rules?: ActiveBlocklistRule[];
}

export interface HoneypotEvent {
  id: string;
  timestamp: string;
  service: 'Cowrie' | 'Dionaea' | 'ElasticPot' | 'Conpot';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO';
  attackerIp: string;
  attackerCountry: string;
  attackerCountryCode: string;
  targetPort: number;
  message: string;
  details: {
    username?: string;
    password?: string;
    command?: string;
    payloadHash?: string;
    exploitMethod?: string;
    httpMethod?: string;
    httpPath?: string;
    scadaRegister?: string;
    scadaOperation?: string;
  };
}

export interface DeceptionTestResult {
  status?: string;
  execution_time_ms?: number | string;
  deception_payload?: string;
  ai_response?: string;
  [key: string]: any;
}


