import React, { useMemo, useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import * as d3 from 'd3';
import {
  Globe, Shield, AlertTriangle, Radio, CheckCircle, Crosshair, Server, Lock,
  ZoomIn, ZoomOut, Maximize2, X, Terminal, Ban, Fingerprint
} from 'lucide-react';
import { Incident, SystemNode } from '../types';

interface ThreatMapProps {
  incidents: Incident[];
  nodes: SystemNode[];
  isLockdownActive?: boolean;
}

interface MapCountry {
  code: string;
  name: string;
  coordinates: [number, number]; // [longitude, latitude]
}

export interface IPThreatIntel {
  ip: string;
  country: string;
  countryCode: string;
  asn: string;
  organization: string;
  reputationScore: number; // 0 to 100 (high is worse/more threat)
  threatCategory: string;
  riskLevel: 'Critical' | 'High' | 'Medium' | 'Low';
  lastSeen: string;
  totalIncidents: number;
  ptrRecord: string;
  threatDetails: string;
}

// Deterministic generator of Threat Intel metadata based on IP address
const getIPThreatIntel = (ip: string, countryCode: string, countryName: string, category: string = 'Malicious Ingress'): IPThreatIntel => {
  // Simple hash for deterministic, stable values per IP
  const ipHash = ip.split('.').reduce((acc, val) => acc + (parseInt(val) || 0), 0) + countryCode.charCodeAt(0);

  // Deterministic Reputation Score: 68 - 98
  const reputationScore = 68 + (ipHash % 31);

  let riskLevel: 'Critical' | 'High' | 'Medium' | 'Low' = 'Medium';
  if (reputationScore >= 90) riskLevel = 'Critical';
  else if (reputationScore >= 80) riskLevel = 'High';
  else if (reputationScore >= 70) riskLevel = 'Medium';
  else riskLevel = 'Low';

  // Real-world, trustworthy Autonomous Systems (ASNs) and Organizations by Country Code
  let asn = 'AS15169';
  let organization = 'Google Cloud Infrastructure';
  let ptrRecord = `ptr-${ip.replace(/\./g, '-')}.infra.net`;

  switch (countryCode) {
    case 'US':
      if (ipHash % 3 === 0) {
        asn = 'AS7922';
        organization = 'Comcast Cable Communications, LLC';
      } else if (ipHash % 3 === 1) {
        asn = 'AS11351';
        organization = 'Charter Communications (Spectrum)';
      } else {
        asn = 'AS209';
        organization = 'CenturyLink Communications';
      }
      break;
    case 'CN':
      if (ipHash % 2 === 0) {
        asn = 'AS4134';
        organization = 'CHINANET-BACKBONE No.31 Province Node';
      } else {
        asn = 'AS4837';
        organization = 'CHINA UNICOM China169 Backbone';
      }
      break;
    case 'RU':
      if (ipHash % 2 === 0) {
        asn = 'AS12389';
        organization = 'Rostelecom PJSC ISP';
      } else {
        asn = 'AS208722';
        organization = 'JSC ER-Telecom Holding Moscow';
      }
      break;
    case 'NL':
      asn = 'AS49544';
      organization = 'Tor Exit Node Infrastructure';
      ptrRecord = `nl-tor-exit-${ip.replace(/\./g, '-')}.amsterdam.onion.net`;
      break;
    case 'UA':
      asn = 'AS21219';
      organization = 'Ukrtelecom JSC National Backbone';
      break;
    case 'KP':
      asn = 'AS131279';
      organization = 'Ryongsong Cyber Defense Operations';
      ptrRecord = `gw-unit-${ip.replace(/\./g, '-')}.star.co.kp`;
      break;
    case 'BR':
      asn = 'AS27699';
      organization = 'Telefonica Brasil S.A.';
      break;
    case 'IR':
      asn = 'AS12880';
      organization = 'Information Technology Company Iran (TIC)';
      break;
    default:
      asn = `AS${10000 + (ipHash % 50000)}`;
      organization = `${countryName} Autonomous National Transit`;
  }

  const threatDetails = `This address matches high-risk signatures flagged by security feeds. Repetitive brute force ingress, port scans, or SQL Injection templates have targeted production edge interfaces over the last 12-hour audit cycle.`;

  return {
    ip,
    country: countryName,
    countryCode,
    asn,
    organization,
    reputationScore,
    threatCategory: category,
    riskLevel,
    lastSeen: new Date(Date.now() - (ipHash % 45) * 60000).toLocaleTimeString(),
    totalIncidents: (ipHash % 14) + 1,
    ptrRecord,
    threatDetails
  };
};

export const ThreatMap: React.FC<ThreatMapProps> = ({ incidents, nodes, isLockdownActive = false }) => {
  const svgRef = useRef<SVGSVGElement>(null);

  // Custom Zoom and Pan state
  const [zoomTransform, setZoomTransform] = useState({ x: 0, y: 0, k: 1 });
  const [activeSector, setActiveSector] = useState<'global' | 'amer' | 'emea' | 'apac' | 'custom'>('global');

  const [hoveredTarget, setHoveredTarget] = useState<{
    type: 'threat' | 'node';
    name: string;
    details: string;
    count?: number;
    x: number;
    y: number;
  } | null>(null);

  const [activeArcs, setActiveArcs] = useState<{
    id: string;
    from: [number, number];
    to: [number, number];
    severity: string;
    category: string;
    sourceIp: string;
    targetService: string;
  }[]>([]);

  // Track cursor coordinates mapped back to geographical coordinates
  const [mouseCoords, setMouseCoords] = useState<{
    lng: number;
    lat: number;
    x: number;
    y: number;
  } | null>(null);

  // Click-interaction State for selected Threat IP and Dossier
  const [selectedIPIntel, setSelectedIPIntel] = useState<IPThreatIntel | null>(null);
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [dpiLogs, setDpiLogs] = useState<string[]>([]);
  const [isRunningDpi, setIsRunningDpi] = useState(false);
  const [isIPBlocked, setIsIPBlocked] = useState<Record<string, boolean>>({});

  const runDPIAnalysis = (ip: string) => {
    if (isRunningDpi) return;
    setIsRunningDpi(true);
    setDpiLogs([`[INIT] Preparing sandbox environment for ${ip}...`]);

    const logs = [
      `[SCAN] Querying WHOIS & regional registry databases...`,
      `[INFO] Route path resolved. Validating cryptographically signed network certificate...`,
      `[PORT] Initiating syn packet fingerprint on active ingress nodes...`,
      `[ALERT] Unrecognized TCP handshakes flagged on ports 80, 443, 22.`,
      `[WARN] Target reputation calculated: ${selectedIPIntel ? selectedIPIntel.reputationScore : 88}/100.`,
      `[SUCCESS] Deep inspection completed. Local mitigations aligned.`
    ];

    logs.forEach((log, index) => {
      setTimeout(() => {
        setDpiLogs(prev => [...prev, log]);
        if (index === logs.length - 1) {
          setIsRunningDpi(false);
        }
      }, (index + 1) * 600);
    });
  };

  const handleCountryClick = (tc: MapCountry) => {
    const countryIncidents = incidents.filter(inc => inc.countryCode === tc.code);
    if (countryIncidents.length > 0) {
      const firstIp = countryIncidents[0].sourceIp;
      setSelectedIp(firstIp);
      const intel = getIPThreatIntel(firstIp, tc.code, tc.name, countryIncidents[0].category);
      setSelectedIPIntel(intel);
    } else {
      const fallbackIps: Record<string, string> = {
        'US': '198.51.100.42',
        'CN': '222.186.190.5',
        'RU': '185.220.101.5',
        'NL': '82.197.202.13',
        'UA': '195.138.80.34',
        'KP': '175.45.176.12',
        'BR': '191.240.231.55',
        'IR': '5.218.12.19',
      };
      const ip = fallbackIps[tc.code] || '192.0.2.1';
      setSelectedIp(ip);
      const intel = getIPThreatIntel(ip, tc.code, tc.name, 'Pre-Ingress Scanning');
      setSelectedIPIntel(intel);
    }
    // Also trigger smooth camera zoom focus
    setActiveSector('custom');
    zoomToGeoCoordinate(tc.coordinates[0], tc.coordinates[1], 2.8);
    // Reset DPI scanner logs
    setDpiLogs([]);
  };

  const handleNodeClick = (n: SystemNode) => {
    const nodeIncidents = incidents.filter(inc => inc.targetService === n.id);
    if (nodeIncidents.length > 0) {
      const firstInc = nodeIncidents[0];
      const tc = threatCountries.find(c => c.code === firstInc.countryCode) || { name: firstInc.countryCode, coordinates: [0, 0] as [number, number] };
      setSelectedIp(firstInc.sourceIp);
      const intel = getIPThreatIntel(firstInc.sourceIp, firstInc.countryCode, tc.name, firstInc.category);
      setSelectedIPIntel(intel);
    } else {
      setSelectedIp(null);
      setSelectedIPIntel({
        ip: 'SECURE_NODE_OK',
        country: n.region,
        countryCode: n.id.split('-')[1] || 'GLOBAL',
        asn: 'N/A',
        organization: 'Enterprise Sovereign Shield Operations',
        reputationScore: 0,
        threatCategory: 'None Detected',
        riskLevel: 'Low',
        lastSeen: new Date().toLocaleTimeString(),
        totalIncidents: 0,
        ptrRecord: `${n.id.toLowerCase()}.edge-gateway.internal`,
        threatDetails: `Sovereign edge interface ${n.name} is fully green with 0 anomalies logged over the active monitoring cycle.`
      });
    }
    // Zoom to node
    const coords = nodeCoordinates[n.id];
    if (coords) {
      setActiveSector('custom');
      zoomToGeoCoordinate(coords[0], coords[1], 2.8);
    }
    setDpiLogs([]);
  };

  // 1. Core country centroid registry for incident origins
  const threatCountries: MapCountry[] = useMemo(() => [
    { code: 'US', name: 'United States', coordinates: [-95.7, 37.1] },
    { code: 'CN', name: 'China', coordinates: [104.2, 35.9] },
    { code: 'RU', name: 'Russian Federation', coordinates: [105.3, 61.5] },
    { code: 'NL', name: 'Netherlands', coordinates: [5.3, 52.1] },
    { code: 'UA', name: 'Ukraine', coordinates: [31.2, 48.4] },
    { code: 'KP', name: 'North Korea', coordinates: [127.5, 40.3] },
    { code: 'BR', name: 'Brazil', coordinates: [-51.9, -14.2] },
    { code: 'IR', name: 'Iran', coordinates: [53.7, 32.4] },
  ], []);

  // 2. Protected infrastructure coordinates mapping
  const nodeCoordinates: Record<string, [number, number]> = useMemo(() => ({
    'NODE-US-EAST': [-77.0, 38.9],    // Virginia, USA
    'NODE-EU-WEST': [-6.3, 53.3],     // Dublin, Ireland
    'NODE-AP-SOUTH': [72.9, 19.1],    // Mumbai, India
    'NODE-US-WEST': [-120.5, 43.8],   // Oregon, USA
    'NODE-SA-EAST': [-46.6, -23.5],   // São Paulo, Brazil
  }), []);

  // High Fidelity low-poly tactical world layout representing actual continent profiles
  const detailedContinents = useMemo(() => [
    // North America (High Fidelity)
    [
      [-168, 66], [-141, 70], [-120, 72], [-100, 68], [-80, 62], [-60, 65], [-55, 55], [-62, 45],
      [-80, 25], [-99, 15], [-105, 20], [-110, 23], [-115, 30], [-125, 40], [-125, 48], [-140, 60], [-168, 66]
    ],
    // Central America / Mexico link
    [
      [-99, 15], [-90, 14], [-83, 9], [-77, 8], [-80, 16], [-99, 15]
    ],
    // South America (High Fidelity)
    [
      [-77, 8], [-72, 11], [-60, 10], [-50, -2], [-35, -6], [-40, -20], [-60, -35], [-70, -53],
      [-74, -53], [-72, -40], [-79, -30], [-81, -5], [-77, 8]
    ],
    // Africa (High Fidelity)
    [
      [-17, 15], [-14, 20], [-6, 36], [10, 37], [20, 32], [32, 31], [34, 27], [43, 12],
      [51, 11], [46, -1], [40, -10], [33, -27], [20, -35], [15, -35], [10, -15], [8, 5], [-17, 15]
    ],
    // Europe & Asia (Eurasia - High Fidelity)
    [
      [-9, 39], [-9, 43], [-5, 48], [-5, 50], [5, 51], [5, 58], [15, 58], [20, 65], [25, 71],
      [40, 68], [60, 70], [80, 73], [100, 75], [120, 74], [140, 72], [160, 70], [170, 66],
      [140, 45], [130, 35], [120, 38], [115, 20], [105, 15], [96, 16], [90, 10], [80, 8],
      [75, 12], [68, 25], [60, 25], [50, 13], [44, 15], [40, 26], [35, 30], [26, 39], [15, 38],
      [10, 36], [-9, 39]
    ],
    // Scandinavia
    [
      [5, 58], [10, 60], [18, 59], [22, 69], [15, 71], [10, 65], [5, 58]
    ],
    // India
    [
      [68, 25], [72, 19], [79, 8], [80, 16], [88, 22], [68, 25]
    ],
    // Indochina & Southeast Asia
    [
      [96, 16], [105, 20], [109, 10], [105, 2], [100, 5], [96, 16]
    ],
    // Australia
    [
      [113, -22], [125, -15], [136, -12], [142, -11], [153, -28], [148, -35], [142, -38],
      [115, -34], [113, -22]
    ],
    // Greenland
    [
      [-73, 78], [-60, 82], [-30, 83], [-10, 75], [-40, 60], [-55, 60], [-73, 78]
    ],
    // Great Britain & Ireland
    [
      [-10, 50], [-5, 50], [-2, 55], [-4, 59], [-8, 55], [-10, 50]
    ],
    // Japan
    [
      [130, 32], [135, 35], [140, 38], [142, 43], [140, 45], [135, 40], [130, 32]
    ],
    // Madagascar
    [
      [43, -12], [47, -15], [50, -25], [45, -25], [43, -12]
    ]
  ], []);

  // 3. Map Projection Calculations using D3 Mercator
  const width = 800;
  const height = 400;

  const projection = useMemo(() => {
    return d3.geoMercator()
      .scale(122)
      .translate([width / 2, height / 2 + 35]);
  }, [width, height]);

  // Project continent coordinates to SVG pixels
  const projectedContinents = useMemo(() => {
    return detailedContinents.map(poly => {
      return poly.map(coord => {
        const proj = projection([coord[0], coord[1]]);
        return proj ? `${proj[0]},${proj[1]}` : '';
      }).filter(Boolean).join(' ');
    });
  }, [detailedContinents, projection]);

  // Initialize D3 Zoom Behavior
  useEffect(() => {
    const svgEl = svgRef.current;
    if (!svgEl) return;

    const zoomBehavior = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([1, 8]) // Allows inspection up to 8x precision
      .translateExtent([[0, 0], [width, height]]) // Map boundary locks
      .on('zoom', (event) => {
        setZoomTransform({
          x: event.transform.x,
          y: event.transform.y,
          k: event.transform.k
        });
        if (event.sourceEvent) {
          setActiveSector('custom');
        }
      });

    const d3Svg = d3.select(svgEl);
    d3Svg.call(zoomBehavior);

    // Initial setup with base transform
    d3Svg.call(zoomBehavior.transform, d3.zoomIdentity);
  }, [width, height]);

  // Custom Zoom Helper: Center on specific geographic coordinate with smooth transitions
  const zoomToGeoCoordinate = (longitude: number, latitude: number, scale: number) => {
    if (!svgRef.current) return;
    const proj = projection([longitude, latitude]);
    if (!proj) return;

    const targetX = width / 2 - proj[0] * scale;
    const targetY = height / 2 - proj[1] * scale;

    d3.select(svgRef.current)
      .transition()
      .duration(750)
      .call(
        d3.zoom<SVGSVGElement, unknown>().transform,
        d3.zoomIdentity.translate(targetX, targetY).scale(scale)
      );
  };

  const handleZoomIn = () => {
    if (!svgRef.current) return;
    d3.select(svgRef.current)
      .transition()
      .duration(300)
      .call(d3.zoom<SVGSVGElement, unknown>().scaleBy, 1.5);
  };

  const handleZoomOut = () => {
    if (!svgRef.current) return;
    d3.select(svgRef.current)
      .transition()
      .duration(300)
      .call(d3.zoom<SVGSVGElement, unknown>().scaleBy, 0.67);
  };

  const handleResetZoom = () => {
    if (!svgRef.current) return;
    d3.select(svgRef.current)
      .transition()
      .duration(500)
      .call(d3.zoom<SVGSVGElement, unknown>().transform, d3.zoomIdentity);
  };

  // High Density Tactical Sector Presets
  const sectors = useMemo(() => [
    { id: 'global', label: 'GLOBAL', lng: 0, lat: 0, k: 1 },
    { id: 'amer', label: 'AMER (WEST)', lng: -85, lat: 20, k: 2.1 },
    { id: 'emea', label: 'EMEA (CENTRAL)', lng: 20, lat: 30, k: 2.3 },
    { id: 'apac', label: 'APAC (EAST)', lng: 115, lat: 15, k: 2.4 },
  ] as const, []);

  const handleSectorChange = (id: typeof sectors[number]['id']) => {
    setActiveSector(id);
    if (id === 'global') {
      handleResetZoom();
    } else {
      const sector = sectors.find(s => s.id === id);
      if (sector) {
        zoomToGeoCoordinate(sector.lng, sector.lat, sector.k);
      }
    }
  };

  // Track map cursor and invert coordinates back to WGS84 format taking active zoom/pan into account
  const handleMouseMove = (e: React.MouseEvent<SVGSVGElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;

    const svgX = (x / rect.width) * width;
    const svgY = (y / rect.height) * height;

    // Inverse calculations for zoom transform state
    const unzoomedX = (svgX - zoomTransform.x) / zoomTransform.k;
    const unzoomedY = (svgY - zoomTransform.y) / zoomTransform.k;

    const inverted = projection && typeof projection.invert === 'function' ? projection.invert([unzoomedX, unzoomedY]) : null;
    if (inverted) {
      setMouseCoords({
        lng: inverted[0],
        lat: inverted[1],
        x: svgX,
        y: svgY
      });
    }

  };

  const handleMouseLeave = () => {
    setMouseCoords(null);
  };

  // Calculate incident stats by country
  const countryIncidentStats = useMemo(() => {
    const stats: Record<string, { count: number; critical: number; high: number }> = {};

    // Initialize standard list
    threatCountries.forEach(tc => {
      stats[tc.code] = { count: 0, critical: 0, high: 0 };
    });

    incidents.forEach(inc => {
      const code = inc.countryCode;
      if (!stats[code]) {
        stats[code] = { count: 0, critical: 0, high: 0 };
      }
      stats[code].count++;
      if (inc.severity === 'critical') stats[code].critical++;
      if (inc.severity === 'high') stats[code].high++;
    });

    return stats;
  }, [incidents, threatCountries]);

  // 4. Trace dynamic Bezier Arcs for active threat simulation
  useEffect(() => {
    if (isLockdownActive || incidents.length === 0) {
      setActiveArcs([]);
      return;
    }

    // Grab the 5 most recent active incidents for arc visualization
    const recentIncidents = incidents.slice(0, 5);
    const newArcs = recentIncidents.map(inc => {
      const fromCountry = threatCountries.find(tc => tc.code === inc.countryCode);
      const toNodeCoord = nodeCoordinates[inc.targetService] || nodeCoordinates['NODE-US-EAST'];

      if (fromCountry && toNodeCoord) {
        return {
          id: inc.id,
          from: fromCountry.coordinates,
          to: toNodeCoord,
          severity: inc.severity,
          category: inc.category,
          sourceIp: inc.sourceIp,
          targetService: inc.targetService
        };
      }
      return null;
    }).filter(Boolean) as {
      id: string;
      from: [number, number];
      to: [number, number];
      severity: string;
      category: string;
      sourceIp: string;
      targetService: string;
    }[];

    setActiveArcs(newArcs);
  }, [incidents, threatCountries, nodeCoordinates, isLockdownActive]);

  // SVG Helper to calculate bezier path control points
  const calculateCurvePath = (fromProj: [number, number], toProj: [number, number]) => {
    const [x1, y1] = fromProj;
    const [x2, y2] = toProj;

    // Calculate control point for standard arched Bezier curve
    const dx = x2 - x1;
    const dy = y2 - y1;
    const dr = Math.sqrt(dx * dx + dy * dy);

    // Make bend proportional to distance
    return `M${x1},${y1} A${dr},${dr * 1.2} 0 0,1 ${x2},${y2}`;
  };

  const getSeverityColor = (sev: string) => {
    if (sev === 'critical') return '#f87171'; // red-400
    if (sev === 'high') return '#fb923c';     // orange-400
    if (sev === 'medium') return '#facc15';   // yellow-400
    return '#818cf8';                         // indigo-400
  };

  // Human-readable lat/lng parsing helper
  const formatLatLng = (val: number, isLat: boolean) => {
    const absolute = Math.abs(val).toFixed(4);
    const direction = isLat
      ? (val >= 0 ? 'N' : 'S')
      : (val >= 0 ? 'E' : 'W');
    return `${absolute}° ${direction}`;
  };

  return (
    <div
      id="threat-world-map-container"
      className="bg-white dark:bg-[#050b18]/60 backdrop-blur-xl border border-slate-200 dark:border-slate-800/80 rounded-2xl p-5 shadow-xs dark:shadow-xl relative overflow-hidden group hover:border-slate-300 dark:hover:border-slate-700/60 transition duration-300 flex flex-col"
    >
      {/* Top border ambient glow accent */}
      <div className="absolute top-0 left-0 right-0 h-[1.5px] bg-gradient-to-r from-transparent via-sky-500/20 dark:via-indigo-500/20 to-transparent group-hover:via-sky-500/40 dark:group-hover:via-indigo-500/40 transition-all duration-1000" />

      {/* Header with detailed operational telemetry metadata */}
      <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4 pb-4 border-b border-slate-200 dark:border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <span className="flex h-2 w-2 relative">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-rose-500"></span>
            </span>
            <Globe className="w-4.5 h-4.5 text-sky-600 dark:text-indigo-400 animate-spin-slow" />
            <h2 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider font-mono">
              Global Sovereign Ingress Threat Map
            </h2>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 font-sans">
            Cryptographically signed perimeter firewall ledger mapping and active origin detection vectors
          </p>
        </div>

        {/* Security Trust Badges & Ledger SLA Status */}
        <div className="flex flex-wrap items-center gap-3">
          {isLockdownActive && (
            <div className="bg-rose-500/10 dark:bg-rose-950/40 border border-rose-500/30 dark:border-rose-500/50 px-2.5 py-1 rounded-md text-[9px] font-mono flex items-center gap-1.5 text-rose-600 dark:text-rose-300 animate-pulse font-bold">
              <Lock className="w-3 h-3 text-rose-500 dark:text-rose-400" />
              <span>ZERO-TRUST KILL-SWITCH ACTIVE • INGRESS SEALED</span>
            </div>
          )}
          <div className="bg-slate-100 dark:bg-slate-950/80 border border-slate-200 dark:border-slate-800/80 px-2.5 py-1 rounded-md text-[9px] font-mono flex items-center gap-1.5 text-slate-600 dark:text-slate-400">
            <Lock className="w-3 h-3 text-sky-500 dark:text-cyan-400" />
            <span>VERIFICATION: <span className="text-sky-600 dark:text-cyan-400 font-bold">AES-256 GCM</span></span>
          </div>
          <div className="bg-slate-100 dark:bg-slate-950/80 border border-slate-200 dark:border-slate-800/80 px-2.5 py-1 rounded-md text-[9px] font-mono flex items-center gap-1.5 text-slate-600 dark:text-slate-400">
            <Shield className="w-3 h-3 text-emerald-500 dark:text-emerald-400" />
            <span>LEDGER: <span className="text-emerald-600 dark:text-emerald-400 font-bold">COMPLIANT</span></span>
          </div>
          <div className="bg-sky-500/10 dark:bg-sky-950/25 border border-sky-500/20 dark:border-sky-800/40 px-2.5 py-1 rounded-md text-[9px] font-mono flex items-center gap-1.5 text-sky-700 dark:text-sky-300">
            <Server className="w-3 h-3 text-sky-500 dark:text-sky-400 animate-pulse" />
            <span>SLA UPTIME: <span className="text-sky-600 dark:text-sky-400 font-bold">99.999%</span></span>
          </div>
        </div>
      </div>

      {/* Main dashboard content divided in Map & Ingress Feed Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 mt-4">

        {/* Left column: SVG Interactive Geolocation projection (Occupies 3/4) */}
        <div className="lg:col-span-3 relative bg-slate-50 dark:bg-slate-950/40 border border-slate-200 dark:border-slate-900 rounded-xl p-2 select-none overflow-hidden">

          {/* Scanning sweep laser overlay line */}
          <div className="absolute inset-0 bg-[linear-gradient(to_bottom,transparent_49%,rgba(99,102,241,0.02)_50%,rgba(99,102,241,0.06)_51%,transparent_53%)] bg-[length:100%_200%] animate-[scan_6s_linear_infinite] pointer-events-none" />

          {/* Floating High-Precision Zoom & Sector Navigation Overlay Panel */}
          <div className="absolute top-4 right-4 flex flex-col sm:flex-row items-stretch sm:items-center gap-2 z-20">

            {/* Sector shortcuts */}
            <div className="flex bg-white/95 dark:bg-slate-950/90 border border-slate-200 dark:border-slate-800/85 rounded-lg p-0.5 shadow-md dark:shadow-2xl backdrop-blur-md">
              {sectors.map((s) => (
                <button
                  key={s.id}
                  onClick={() => handleSectorChange(s.id)}
                  className={`px-2.5 py-1 rounded-md text-[9px] font-mono font-bold transition-all duration-200 cursor-pointer ${activeSector === s.id
                    ? 'bg-sky-500/20 text-sky-700 dark:bg-indigo-600/35 dark:text-indigo-300 border border-sky-500/40 dark:border-indigo-500/45'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white border border-transparent'
                    }`}
                  title={`Focus camera view on ${s.label}`}
                >
                  {s.label}
                </button>
              ))}
            </div>

            {/* Direct zoom buttons */}
            <div className="flex bg-white/95 dark:bg-slate-950/90 border border-slate-200 dark:border-slate-800/85 rounded-lg p-0.5 shadow-md dark:shadow-2xl backdrop-blur-md divide-x divide-slate-200 dark:divide-slate-800/60">
              <button
                onClick={handleZoomIn}
                className="p-1.5 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition cursor-pointer"
                title="Zoom In"
              >
                <ZoomIn className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={handleZoomOut}
                className="p-1.5 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition cursor-pointer"
                title="Zoom Out"
              >
                <ZoomOut className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={handleResetZoom}
                className="p-1.5 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition cursor-pointer"
                title="Reset Camera Zoom"
              >
                <Maximize2 className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          <svg
            ref={svgRef}
            viewBox={`0 0 ${width} ${height}`}
            className="w-full h-auto text-slate-700 relative z-10 cursor-grab active:cursor-grabbing"
            onMouseMove={handleMouseMove}
            onMouseLeave={handleMouseLeave}
          >
            {/* Wrap map contents inside a transform group bound to D3 Zoom State */}
            <g transform={`translate(${zoomTransform.x}, ${zoomTransform.y}) scale(${zoomTransform.k})`}>

              {/* Subtle grid lines background (Graticule map style) with vector stroke compensation */}
              <g className="opacity-[0.04] stroke-indigo-400 stroke-[0.5px]">
                {d3.range(-180, 180, 15).map(lon => {
                  const start = projection([lon, -80]);
                  const end = projection([lon, 80]);
                  if (!start || !end) return null;
                  return (
                    <line
                      key={`lon-${lon}`}
                      x1={start[0]}
                      y1={start[1]}
                      x2={end[0]}
                      y2={end[1]}
                      vectorEffect="non-scaling-stroke"
                    />
                  );
                })}
                {d3.range(-80, 81, 15).map(lat => {
                  const start = projection([-180, lat]);
                  const end = projection([180, lat]);
                  if (!start || !end) return null;
                  return (
                    <line
                      key={`lat-${lat}`}
                      x1={start[0]}
                      y1={start[1]}
                      x2={end[0]}
                      y2={end[1]}
                      vectorEffect="non-scaling-stroke"
                    />
                  );
                })}
              </g>

              {/* Topographic detailed landmass shapes with vector non-scaling-stroke for extreme sharpness */}
              <g>
                {projectedContinents.map((points, idx) => (
                  <polygon
                    key={`continent-${idx}`}
                    points={points}
                    className="fill-slate-200/90 dark:fill-[#0a162d]/45 stroke-slate-300 dark:stroke-indigo-950/50 stroke-[1.2px] transition-all duration-300 hover:fill-slate-300 dark:hover:fill-[#0d1f3f]/60"
                    vectorEffect="non-scaling-stroke"
                  />
                ))}
              </g>

              {/* Active high-precision dynamic threat Bezier trails */}
              <g>
                <AnimatePresence>
                  {activeArcs.map(arc => {
                    const fromProj = projection(arc.from);
                    const toProj = projection(arc.to);

                    if (!fromProj || !toProj) return null;
                    const pathStr = calculateCurvePath(fromProj, toProj);
                    const color = getSeverityColor(arc.severity);

                    return (
                      <g key={`arc-group-${arc.id}`}>
                        {/* Pulsating broad background blur trail */}
                        <motion.path
                          d={pathStr}
                          fill="transparent"
                          stroke={color}
                          strokeWidth="3"
                          className="opacity-15 blur-[1.5px] pointer-events-none"
                          vectorEffect="non-scaling-stroke"
                          initial={{ pathLength: 0 }}
                          animate={{ pathLength: 1 }}
                          exit={{ opacity: 0 }}
                          transition={{ duration: 1.2, ease: 'easeOut' }}
                        />

                        {/* Sharp high-contrast core path */}
                        <motion.path
                          id={`threat-path-${arc.id}`}
                          d={pathStr}
                          fill="transparent"
                          stroke={color}
                          strokeWidth="1.2"
                          className="opacity-70 pointer-events-none"
                          vectorEffect="non-scaling-stroke"
                          initial={{ pathLength: 0 }}
                          animate={{ pathLength: 1 }}
                          exit={{ opacity: 0 }}
                          transition={{ duration: 1.0, ease: 'easeOut' }}
                        />

                        {/* Flowing dashes trail animation from source to target proxy */}
                        <motion.path
                          d={pathStr}
                          fill="transparent"
                          stroke={color}
                          strokeWidth="1.5"
                          className="opacity-90 pointer-events-none"
                          vectorEffect="non-scaling-stroke"
                          strokeDasharray="4 6"
                          animate={{ strokeDashoffset: [0, -20] }}
                          transition={{
                            repeat: Infinity,
                            ease: 'linear',
                            duration: 1.5
                          }}
                        />

                        {/* Scrolling Source IP Text Label along the path trajectory */}
                        <text
                          dy="-3"
                          className="font-mono font-bold fill-rose-300/90 pointer-events-none select-none drop-shadow-[0_1px_2px_rgba(0,0,0,0.9)]"
                          style={{ fontSize: `${Math.max(5, 7.5 / Math.sqrt(zoomTransform.k))}px` }}
                        >
                          <textPath href={`#threat-path-${arc.id}`} startOffset="20%">
                            <animate
                              attributeName="startOffset"
                              from="0%"
                              to="100%"
                              dur="6s"
                              repeatCount="indefinite"
                            />
                            {arc.sourceIp} ⚡ {arc.targetService.replace('NODE-', '')} [{arc.category}]
                          </textPath>
                        </text>

                        {/* High-fidelity custom pulsed SVG ripple at Threat Origin Coordinate */}
                        <g transform={`translate(${fromProj[0]}, ${fromProj[1]})`} className="pointer-events-none">
                          <motion.circle
                            r={2 / Math.sqrt(zoomTransform.k)}
                            fill="none"
                            stroke={color}
                            strokeWidth={1.5 / Math.sqrt(zoomTransform.k)}
                            initial={{ r: 2 / Math.sqrt(zoomTransform.k), opacity: 0.9 }}
                            animate={{ r: 35 / Math.sqrt(zoomTransform.k), opacity: 0 }}
                            transition={{
                              repeat: Infinity,
                              duration: 2.5,
                              ease: "easeOut"
                            }}
                          />
                          <motion.circle
                            r={2 / Math.sqrt(zoomTransform.k)}
                            fill="none"
                            stroke={color}
                            strokeWidth={1.0 / Math.sqrt(zoomTransform.k)}
                            initial={{ r: 2 / Math.sqrt(zoomTransform.k), opacity: 0.9 }}
                            animate={{ r: 22 / Math.sqrt(zoomTransform.k), opacity: 0 }}
                            transition={{
                              repeat: Infinity,
                              duration: 2.5,
                              delay: 0.8,
                              ease: "easeOut"
                            }}
                          />
                          <motion.circle
                            r={2 / Math.sqrt(zoomTransform.k)}
                            fill="none"
                            stroke={color}
                            strokeWidth={0.5 / Math.sqrt(zoomTransform.k)}
                            initial={{ r: 2 / Math.sqrt(zoomTransform.k), opacity: 0.9 }}
                            animate={{ r: 12 / Math.sqrt(zoomTransform.k), opacity: 0 }}
                            transition={{
                              repeat: Infinity,
                              duration: 2.5,
                              delay: 1.6,
                              ease: "easeOut"
                            }}
                          />
                          <motion.circle
                            r={4 / Math.sqrt(zoomTransform.k)}
                            fill={color}
                            initial={{ scale: 0.8, opacity: 0.6 }}
                            animate={{ scale: [1, 1.4, 1], opacity: [0.6, 0.95, 0.6] }}
                            transition={{
                              repeat: Infinity,
                              duration: 1.5,
                              ease: "easeInOut"
                            }}
                          />
                        </g>

                        {/* Floating physical Source IP badge near the origin country centroid */}
                        <g transform={`translate(${fromProj[0]}, ${fromProj[1] - 8 / Math.sqrt(zoomTransform.k)})`} className="pointer-events-none select-none">
                          <rect
                            x={-34 / Math.sqrt(zoomTransform.k)}
                            y={-5 / Math.sqrt(zoomTransform.k)}
                            width={68 / Math.sqrt(zoomTransform.k)}
                            height={10 / Math.sqrt(zoomTransform.k)}
                            rx={2 / Math.sqrt(zoomTransform.k)}
                            className="fill-slate-950/95 stroke-rose-500/50"
                            strokeWidth={0.8 / zoomTransform.k}
                          />
                          <text
                            textAnchor="middle"
                            dy={2.5 / Math.sqrt(zoomTransform.k)}
                            className="font-mono font-bold fill-rose-300"
                            style={{ fontSize: `${Math.max(4.5, 6 / Math.sqrt(zoomTransform.k))}px` }}
                          >
                            {arc.sourceIp}
                          </text>
                        </g>

                        {/* Targeting Reticle & Pulse Wave on the specific regional Edge Proxy node */}
                        <g transform={`translate(${toProj[0]}, ${toProj[1]})`} className="pointer-events-none">
                          <circle
                            r={18 / Math.sqrt(zoomTransform.k)}
                            fill="none"
                            stroke={color}
                            strokeWidth={0.8 / zoomTransform.k}
                            className="opacity-40 animate-ping"
                          />
                          <circle
                            r={12 / Math.sqrt(zoomTransform.k)}
                            fill="none"
                            stroke={color}
                            strokeWidth={1 / zoomTransform.k}
                            strokeDasharray={`${4 / zoomTransform.k} ${4 / zoomTransform.k}`}
                            className="opacity-60"
                          >
                            <animateTransform
                              attributeName="transform"
                              type="rotate"
                              from="0"
                              to="360"
                              dur="10s"
                              repeatCount="indefinite"
                            />
                          </circle>
                        </g>

                        {/* Slidably translated projectile particle vector */}
                        <motion.circle
                          r={3 / Math.sqrt(zoomTransform.k)}
                          fill={color}
                          initial={{ offsetDistance: "0%" }}
                          animate={{ offsetDistance: "100%" }}
                          transition={{ repeat: Infinity, duration: 2.2, ease: 'linear' }}
                          style={{
                            motionPath: `path('${pathStr}')`,
                            motionRotation: 'auto'
                          } as React.CSSProperties & { motionPath: string; motionRotation: string }}
                        />
                      </g>
                    );
                  })}
                </AnimatePresence>
              </g>

              {/* Threat Origin Clusters (highly stylized target trackers) */}
              <g>
                {threatCountries.map(tc => {
                  const proj = projection(tc.coordinates);
                  if (!proj) return null;

                  const stats = countryIncidentStats[tc.code] || { count: 0, critical: 0, high: 0 };
                  const hasIncidents = stats.count > 0;

                  // Scale proportional to incident weight and scale compensated
                  const baseRadius = hasIncidents ? Math.min(16, 5 + stats.count * 1.2) : 3;
                  const compensatedRadius = baseRadius / Math.sqrt(zoomTransform.k);

                  const color = stats.critical > 0 ? 'rgba(239, 68, 68, 0.3)' : stats.high > 0 ? 'rgba(249, 115, 22, 0.3)' : 'rgba(129, 140, 248, 0.15)';
                  const strokeColor = stats.critical > 0 ? '#ef4444' : stats.high > 0 ? '#f97316' : '#6366f1';

                  return (
                    <g
                      key={`country-node-${tc.code}`}
                      transform={`translate(${proj[0]}, ${proj[1]})`}
                      className="cursor-pointer"
                      onClick={() => handleCountryClick(tc)}
                      onMouseEnter={() => {
                        setHoveredTarget({
                          type: 'threat',
                          name: `${tc.name} (${tc.code})`,
                          details: `Active Threat Origin. Blocked packages: ${stats.count}. Severity: ${stats.critical > 0 ? 'CRITICAL' : 'ELEVATED'}. Click to view IP Threat Dossier.`,
                          count: stats.count,
                          x: proj[0] * zoomTransform.k + zoomTransform.x,
                          y: proj[1] * zoomTransform.k + zoomTransform.y - 12,
                        });
                      }}
                      onMouseLeave={() => setHoveredTarget(null)}
                    >
                      {hasIncidents && (
                        <>
                          {/* Dynamic sweep pulse with compensated scale */}
                          <circle
                            r={compensatedRadius * 1.8}
                            fill="transparent"
                            stroke={strokeColor}
                            strokeWidth={0.8 / zoomTransform.k}
                            className="opacity-30 animate-ping"
                          />
                          {/* High density targeting hairs with compensated scale */}
                          <line
                            x1={-8 / zoomTransform.k}
                            y1="0"
                            x2={8 / zoomTransform.k}
                            y2="0"
                            stroke={strokeColor}
                            strokeWidth={0.5 / zoomTransform.k}
                            className="opacity-40"
                          />
                          <line
                            x1="0"
                            y1={-8 / zoomTransform.k}
                            x2="0"
                            y2={8 / zoomTransform.k}
                            stroke={strokeColor}
                            strokeWidth={0.5 / zoomTransform.k}
                            className="opacity-40"
                          />
                        </>
                      )}
                      <circle
                        r={compensatedRadius}
                        fill={color}
                        stroke={strokeColor}
                        strokeWidth={0.8 / zoomTransform.k}
                        className="transition-all duration-300"
                      />
                      <circle
                        r={Math.max(1, 2 / Math.sqrt(zoomTransform.k))}
                        fill={hasIncidents ? strokeColor : '#475569'}
                      />
                    </g>
                  );
                })}
              </g>

              {/* Secure Sovereign Node Shields */}
              <g>
                {nodes.map(n => {
                  const coords = nodeCoordinates[n.id];
                  if (!coords) return null;

                  const proj = projection(coords);
                  if (!proj) return null;

                  const isOperational = n.status === 'operational';
                  const color = isOperational ? '#06b6d4' : '#f59e0b';

                  return (
                    <g
                      key={`infra-node-${n.id}`}
                      transform={`translate(${proj[0]}, ${proj[1]})`}
                      className="cursor-pointer"
                      onClick={() => handleNodeClick(n)}
                      onMouseEnter={() => {
                        setHoveredTarget({
                          type: 'node',
                          name: n.name,
                          details: `Secure sovereign node | SLA: Active | Health: 100% | Latency: ${n.latency}ms. Click to view targets.`,
                          x: proj[0] * zoomTransform.k + zoomTransform.x,
                          y: proj[1] * zoomTransform.k + zoomTransform.y - 12,
                        });
                      }}
                      onMouseLeave={() => setHoveredTarget(null)}
                    >
                      {/* Ring aura */}
                      <circle
                        r={10 / Math.sqrt(zoomTransform.k)}
                        fill="transparent"
                        stroke={color}
                        strokeWidth={1.2 / zoomTransform.k}
                        className="opacity-30"
                      />
                      {isOperational && (
                        <circle
                          r={15 / Math.sqrt(zoomTransform.k)}
                          fill="transparent"
                          stroke="#06b6d4"
                          strokeWidth={0.8 / zoomTransform.k}
                          className="opacity-20 animate-pulse"
                        />
                      )}
                      {/* Compact crosshair design for operational feel */}
                      <path
                        d="M-4,-4 L4,-4 L4,0 C4,3 0,5 0,5 C0,5 -4,3 -4,0 Z"
                        fill={color}
                        className="opacity-90"
                        transform={`scale(${1 / Math.sqrt(zoomTransform.k)})`}
                      />
                    </g>
                  );
                })}
              </g>

            </g>
          </svg>

          {/* Integrated WGS84 Cursor GPS HUD Overlay */}
          <div className="absolute bottom-3 left-3 bg-slate-950/90 border border-slate-800 rounded px-2.5 py-1.5 text-[9px] font-mono text-slate-400 z-20 shadow-lg flex items-center gap-3 backdrop-blur-md">
            <div className="flex items-center gap-1.5">
              <Crosshair className="w-3 h-3 text-cyan-400 animate-spin-slow" />
              <span className="text-slate-500">CURSOR GRID:</span>
              <span className="text-white font-bold">
                {mouseCoords
                  ? `${formatLatLng(mouseCoords.lat, true)} , ${formatLatLng(mouseCoords.lng, false)}`
                  : 'SEARCHING SAT-LINK...'
                }
              </span>
            </div>
            {mouseCoords && (
              <div className="hidden sm:flex items-center gap-1.5 border-l border-slate-800 pl-3">
                <span className="text-slate-500">PROJ_ID:</span>
                <span className="text-cyan-400 font-bold">EPSG:4326</span>
              </div>
            )}
            <div className="hidden md:flex items-center gap-1.5 border-l border-slate-800 pl-3">
              <span className="text-slate-500">CAMERA RANGE:</span>
              <span className="text-indigo-400 font-bold">{(zoomTransform.k * 100).toFixed(0)}%</span>
            </div>
          </div>

          {/* Map Hover Tooltip Popover */}
          <AnimatePresence>
            {hoveredTarget && (
              <motion.div
                initial={{ opacity: 0, y: 5, scale: 0.95 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: 5, scale: 0.95 }}
                className="absolute pointer-events-none bg-slate-950/95 border border-slate-800 rounded-lg p-3 shadow-2xl z-40 max-w-xs font-mono text-xs"
                style={{
                  left: `${(hoveredTarget.x / width) * 100}%`,
                  top: `${(hoveredTarget.y / height) * 100}%`,
                  transform: 'translate(-50%, -100%)',
                }}
              >
                <div className="flex items-center gap-1.5 font-bold text-white border-b border-slate-900 pb-1.5 mb-1.5">
                  {hoveredTarget.type === 'threat' ? (
                    <AlertTriangle className="w-3.5 h-3.5 text-rose-400 shrink-0 animate-pulse" />
                  ) : (
                    <Shield className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                  )}
                  <span className="truncate">{hoveredTarget.name}</span>
                </div>
                <p className="text-[10px] text-slate-400 leading-normal font-sans">
                  {hoveredTarget.details}
                </p>
                {hoveredTarget.count !== undefined && hoveredTarget.count > 0 && (
                  <div className="mt-1.5 pt-1.5 border-t border-slate-900 flex items-center justify-between text-[9px]">
                    <span className="text-slate-500">INCIDENT CONTEXT</span>
                    <span className="text-rose-400 font-bold">
                      {((hoveredTarget.count / Math.max(1, incidents.length)) * 100).toFixed(0)}% SHARE
                    </span>
                  </div>
                )}
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Right column: Geospatial Threat Feed Stream (Occupies 1/4) */}
        <div className="lg:col-span-1 flex flex-col justify-between bg-slate-50 dark:bg-slate-950/40 border border-slate-200 dark:border-slate-900 rounded-xl p-4 font-mono text-xs overflow-hidden">
          <div>
            <div className="flex items-center justify-between pb-2 border-b border-slate-200 dark:border-slate-900 mb-3">
              <span className="text-[10px] text-slate-600 dark:text-slate-400 font-bold flex items-center gap-1">
                <Radio className="w-3.5 h-3.5 text-rose-500 animate-pulse" />
                INGRESS TELEMETRY FEED
              </span>
              <span className="text-[9px] text-emerald-600 dark:text-emerald-400 bg-emerald-500/10 dark:bg-emerald-950/20 px-1.5 py-0.5 rounded border border-emerald-500/25 dark:border-emerald-900/30">
                SECURE
              </span>
            </div>

            {/* Scrollable list of verified threat origins */}
            <div className="space-y-2.5 max-h-[260px] overflow-y-auto pr-1 scrollbar-thin">
              {incidents.slice(0, 6).map((inc, i) => {
                const isCrit = inc.severity === 'critical';
                const isHigh = inc.severity === 'high';
                const isSelected = inc.sourceIp === selectedIp;

                return (
                  <div
                    key={`feed-item-${inc.id}-${i}`}
                    onClick={() => {
                      const tc = threatCountries.find(c => c.code === inc.countryCode) || { name: inc.countryCode, coordinates: [0, 0] as [number, number], code: inc.countryCode };
                      setSelectedIp(inc.sourceIp);
                      const intel = getIPThreatIntel(inc.sourceIp, inc.countryCode, tc.name, inc.category);
                      setSelectedIPIntel(intel);
                      if (tc.coordinates[0] !== 0) {
                        setActiveSector('custom');
                        zoomToGeoCoordinate(tc.coordinates[0], tc.coordinates[1], 2.8);
                      }
                      setDpiLogs([]);
                    }}
                    className={`p-2 border rounded-md transition flex flex-col gap-1 cursor-pointer active:scale-[0.98] ${isSelected
                      ? 'bg-rose-500/10 dark:bg-rose-950/30 border-rose-500/85 shadow-xs dark:shadow-[0_0_8px_rgba(239,68,68,0.25)]'
                      : 'bg-white dark:bg-slate-950/60 border-slate-200 dark:border-slate-900 hover:border-slate-300 dark:hover:border-slate-800 hover:bg-slate-100/80 dark:hover:bg-slate-900/60'
                      }`}
                    title="Click to view IP Threat Dossier"
                  >
                    <div className="flex items-center justify-between">
                      <span className={`text-[10px] font-bold px-1 rounded ${isCrit
                        ? 'bg-rose-500/15 text-rose-600 dark:text-rose-400 border border-rose-500/25 dark:border-rose-900/30'
                        : isHigh
                          ? 'bg-amber-500/15 text-amber-700 dark:text-orange-400 border border-amber-500/25 dark:border-orange-900/30'
                          : 'bg-sky-500/15 text-sky-700 dark:text-indigo-400 border border-sky-500/25 dark:border-indigo-900/30'
                        }`}>
                        {inc.severity.toUpperCase()}
                      </span>
                      <span className="text-[9px] text-slate-500">
                        {new Date(inc.timestamp).toLocaleTimeString()}
                      </span>
                    </div>

                    <div className="flex justify-between items-center text-[11px] mt-1">
                      <span className="text-slate-900 dark:text-white font-bold">{inc.sourceIp}</span>
                      <span className="text-slate-500 dark:text-slate-400">({inc.countryCode})</span>
                    </div>

                    <div className="flex justify-between items-center text-[10px] text-slate-500 dark:text-slate-400 mt-0.5">
                      <span>Target: {inc.targetService.split('-').slice(-1)[0]}</span>
                      <span className="text-sky-600 dark:text-indigo-400 font-bold">{inc.category}</span>
                    </div>
                  </div>
                );
              })}
              {incidents.length === 0 && (
                <div className="text-center py-6 text-slate-400 dark:text-slate-500 text-[11px]">
                  No incoming packets reported in buffer.
                </div>
              )}
            </div>
          </div>

          {/* Secure integrity telemetry seal indicator */}
          <div className="mt-4 pt-3 border-t border-slate-200 dark:border-slate-900 flex flex-col gap-2">
            <div className="flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-emerald-500 dark:text-emerald-400" />
              <div className="flex flex-col">
                <span className="text-[9px] text-slate-500">INTEGRITY COMPLIANCE</span>
                <span className="text-[10px] text-emerald-600 dark:text-emerald-400 font-bold">VERIFIED LEDGER SYSTEM</span>
              </div>
            </div>
            <p className="text-[9px] text-slate-500 font-sans leading-normal">
              Active packets validated via decentralized firewall rule compliance models. Logs parsed inside sovereign sandbox.
            </p>
          </div>
        </div>

      </div>

      {/* Grid footer summary ledger cells */}
      <div className="mt-5 grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3 border-t border-slate-200 dark:border-slate-850 pt-4">
        {threatCountries.map(tc => {
          const stats = countryIncidentStats[tc.code] || { count: 0, critical: 0, high: 0 };
          const activeRatio = incidents.length > 0 ? (stats.count / incidents.length) * 100 : 0;

          return (
            <div
              key={`ledger-cell-${tc.code}`}
              className="bg-slate-50 dark:bg-slate-950/40 border border-slate-200 dark:border-slate-900 hover:border-slate-300 dark:hover:border-slate-800 rounded-lg p-2 flex flex-col font-mono transition cursor-pointer active:scale-[0.98]"
              onClick={() => handleCountryClick(tc)}
              title={`Click to focus coordinates and open IP Threat Dossier for ${tc.name}`}
            >
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-slate-600 dark:text-slate-400 font-bold">{tc.code}</span>
                <span className={`w-2 h-2 rounded-full ${stats.count > 0 ? (stats.critical > 0 ? 'bg-rose-500 animate-pulse' : 'bg-amber-500') : 'bg-slate-300 dark:bg-slate-700'}`} />
              </div>
              <span className="text-xs text-slate-900 dark:text-white font-bold mt-1.5">{tc.name.split(' ')[0]}</span>
              <div className="flex items-end justify-between mt-1 text-[10px]">
                <span className="text-slate-500 font-mono text-[9px]">EVENTS</span>
                <span className={`font-bold ${stats.count > 0 ? 'text-rose-600 dark:text-rose-400' : 'text-slate-500 dark:text-slate-400'}`}>
                  {stats.count} ({activeRatio.toFixed(0)}%)
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Dynamic Slide-in IP Threat Intelligence Dossier Drawer */}
      <AnimatePresence>
        {selectedIPIntel && (
          <motion.div
            initial={{ x: '100%', opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: '100%', opacity: 0 }}
            transition={{ type: 'spring', damping: 25, stiffness: 200 }}
            className="absolute top-0 right-0 h-full w-full sm:w-[440px] bg-white/98 dark:bg-slate-950/98 border-l border-slate-200 dark:border-slate-800/80 shadow-2xl dark:shadow-[0_0_50px_rgba(0,0,0,0.85)] z-50 flex flex-col backdrop-blur-md overflow-hidden font-mono"
          >
            {/* Drawer Header */}
            <div className="p-4 border-b border-slate-200 dark:border-slate-800/80 bg-slate-50 dark:bg-slate-900/40 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Fingerprint className="w-5 h-5 text-rose-500 animate-pulse" />
                <div className="flex flex-col">
                  <span className="text-[10px] text-slate-500 font-bold tracking-wider">THREAT INTELLIGENCE SYSTEM</span>
                  <h3 className="text-xs text-slate-900 dark:text-white font-bold font-mono tracking-widest">INGRESS DOSSIER</h3>
                </div>
              </div>
              <button
                onClick={() => setSelectedIPIntel(null)}
                className="p-1 rounded-md bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:border-slate-300 dark:hover:border-slate-700 transition active:scale-95"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Scrollable Dossier Content */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4 scrollbar-thin">

              {/* Highlight Target IP and Risk Badge */}
              <div className="bg-slate-50 dark:bg-slate-900/30 border border-slate-200 dark:border-slate-800/50 rounded-lg p-4 flex flex-col gap-2 relative overflow-hidden">
                <div className="absolute top-0 right-0 w-32 h-32 bg-rose-500/5 rounded-full blur-3xl pointer-events-none" />
                <span className="text-[9px] text-slate-500">TARGET SOURCE IP ADDRESS</span>
                <div className="flex items-center justify-between">
                  <h2 className="text-xl font-bold text-slate-900 dark:text-white tracking-tight">{selectedIPIntel.ip}</h2>
                  <span className={`text-[9px] font-bold px-2 py-0.5 rounded border ${selectedIPIntel.riskLevel === 'Critical'
                    ? 'bg-rose-500/10 dark:bg-rose-950/50 border-rose-500/30 dark:border-rose-800 text-rose-600 dark:text-rose-400'
                    : selectedIPIntel.riskLevel === 'High'
                      ? 'bg-amber-500/10 dark:bg-orange-950/50 border-amber-500/30 dark:border-orange-800 text-amber-700 dark:text-orange-400'
                      : selectedIPIntel.riskLevel === 'Medium'
                        ? 'bg-yellow-500/10 dark:bg-amber-950/50 border-yellow-500/30 dark:border-amber-800 text-yellow-700 dark:text-amber-400'
                        : 'bg-emerald-500/10 dark:bg-emerald-950/50 border-emerald-500/30 dark:border-emerald-800 text-emerald-600 dark:text-emerald-400'
                    }`}>
                    {selectedIPIntel.riskLevel.toUpperCase()} RISK
                  </span>
                </div>
              </div>

              {/* Threat Reputation score meter */}
              <div className="bg-slate-50 dark:bg-slate-900/30 border border-slate-200 dark:border-slate-800/50 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[10px] text-slate-500 font-bold tracking-wider font-mono">THREAT REPUTATION SCORE</span>
                  <span className={`text-xs font-bold ${selectedIPIntel.reputationScore >= 90 ? 'text-rose-600 dark:text-rose-400' :
                    selectedIPIntel.reputationScore >= 70 ? 'text-amber-600 dark:text-orange-400' : 'text-sky-600 dark:text-cyan-400'
                    }`}>
                    {selectedIPIntel.reputationScore} / 100
                  </span>
                </div>

                {/* Visual Progress Bar Meter */}
                <div className="h-2 w-full bg-slate-200 dark:bg-slate-950 rounded-full overflow-hidden border border-slate-300 dark:border-slate-900">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${selectedIPIntel.reputationScore}%` }}
                    transition={{ duration: 1.0, ease: 'easeOut' }}
                    className={`h-full rounded-full ${selectedIPIntel.reputationScore >= 90 ? 'bg-gradient-to-r from-orange-500 to-red-500 shadow-[0_0_10px_rgba(239,68,68,0.6)]' :
                      selectedIPIntel.reputationScore >= 70 ? 'bg-gradient-to-r from-amber-500 to-orange-500' :
                        selectedIPIntel.reputationScore > 0 ? 'bg-sky-500' : 'bg-slate-400'
                      }`}
                  />
                </div>

                <div className="flex justify-between items-center mt-2 text-[8px] text-slate-500 font-mono">
                  <span>0 (SAFE)</span>
                  <span>50 (ELEVATED)</span>
                  <span>100 (EXTREME THREAT)</span>
                </div>
              </div>

              {/* Core Intel Metadata Table */}
              <div className="bg-white dark:bg-slate-900/20 border border-slate-200 dark:border-slate-900 rounded-lg overflow-hidden text-[11px]">
                <div className="px-3 py-2 bg-slate-50 dark:bg-slate-900/50 border-b border-slate-200 dark:border-slate-900 font-bold text-slate-700 dark:text-slate-400 text-[10px]">
                  RESOLVED GEO-METRICS & NETWORK INFO
                </div>
                <div className="divide-y divide-slate-200 dark:divide-slate-900/60 font-mono">
                  <div className="p-3 flex justify-between items-center">
                    <span className="text-slate-500">Autonomous System (ASN)</span>
                    <span className="text-slate-900 dark:text-white font-bold font-mono">{selectedIPIntel.asn}</span>
                  </div>
                  <div className="p-3 flex flex-col gap-1">
                    <span className="text-slate-500">Service Provider / Organization</span>
                    <span className="text-slate-800 dark:text-slate-200 font-bold text-left truncate" title={selectedIPIntel.organization}>
                      {selectedIPIntel.organization}
                    </span>
                  </div>
                  <div className="p-3 flex justify-between items-center">
                    <span className="text-slate-500">Reverse DNS (PTR Record)</span>
                    <span className="text-sky-600 dark:text-cyan-400 truncate max-w-[200px]" title={selectedIPIntel.ptrRecord}>
                      {selectedIPIntel.ptrRecord}
                    </span>
                  </div>
                  <div className="p-3 flex justify-between items-center">
                    <span className="text-slate-500">Origin Location</span>
                    <span className="text-slate-900 dark:text-white font-bold flex items-center gap-1">
                      <span className="text-[10px] text-slate-600 dark:text-slate-400 bg-slate-100 dark:bg-slate-900 px-1.5 py-0.5 rounded border border-slate-200 dark:border-slate-800">
                        {selectedIPIntel.countryCode}
                      </span>
                      {selectedIPIntel.country}
                    </span>
                  </div>
                  <div className="p-3 flex justify-between items-center">
                    <span className="text-slate-500">Active Buffer Incursions</span>
                    <span className="text-rose-600 dark:text-rose-400 font-bold">{selectedIPIntel.totalIncidents} events</span>
                  </div>
                </div>
              </div>

              {/* Behavior Analysis Details Text */}
              <div className="bg-slate-50 dark:bg-slate-900/10 border border-slate-200 dark:border-slate-900 rounded-lg p-3 text-[10px] text-slate-600 dark:text-slate-400 leading-relaxed font-sans">
                <span className="block font-mono text-[9px] font-bold text-slate-500 mb-1">SIGNATURE BEHAVIORAL NOTE</span>
                {selectedIPIntel.threatDetails}
              </div>

              {/* Interactive Deep Packet Inspection Terminal module */}
              <div className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-900 rounded-lg overflow-hidden">
                <div className="px-3 py-2 bg-slate-100 dark:bg-slate-900/50 border-b border-slate-200 dark:border-slate-900 flex justify-between items-center">
                  <span className="text-[9px] text-emerald-600 dark:text-emerald-400 font-bold flex items-center gap-1.5 font-mono">
                    <Terminal className="w-3.5 h-3.5 text-emerald-500 animate-pulse" />
                    DEEP PACKET INSPECTION TOOL
                  </span>
                  {selectedIPIntel.ip !== 'SECURE_NODE_OK' && (
                    <button
                      onClick={() => runDPIAnalysis(selectedIPIntel.ip)}
                      disabled={isRunningDpi}
                      className="px-2 py-0.5 rounded text-[8px] font-mono border border-emerald-500/30 dark:border-emerald-900 bg-emerald-500/10 dark:bg-emerald-950/20 text-emerald-700 dark:text-emerald-400 hover:bg-emerald-500/20 dark:hover:bg-emerald-950/40 hover:border-emerald-500/50 transition cursor-pointer"
                    >
                      {isRunningDpi ? 'ANALYZING...' : 'RUN INSPECT'}
                    </button>
                  )}
                </div>

                <div className="p-3 min-h-[100px] bg-slate-950 font-mono text-[9px] text-emerald-400 leading-relaxed space-y-1 max-h-[140px] overflow-y-auto">
                  {dpiLogs.length === 0 ? (
                    <div className="text-slate-500 italic py-2 text-center select-none">
                      Terminal idle. Click Run Inspect above to trace packets...
                    </div>
                  ) : (
                    dpiLogs.map((log, lIdx) => (
                      <div key={`dpi-log-${lIdx}`} className="truncate">
                        {log}
                      </div>
                    ))
                  )}
                  {isRunningDpi && (
                    <div className="text-emerald-400 flex items-center gap-1 animate-pulse italic mt-1">
                      <span>Analyzing telemetry packets...</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Mitigation Firewall Trigger Action */}
              {selectedIPIntel.ip !== 'SECURE_NODE_OK' && (
                <div className="pt-2">
                  <button
                    onClick={() => {
                      const ip = selectedIPIntel.ip;
                      setIsIPBlocked(prev => ({ ...prev, [ip]: !prev[ip] }));
                    }}
                    className={`w-full py-2.5 rounded-lg border text-xs font-bold font-mono transition flex items-center justify-center gap-2 cursor-pointer ${isIPBlocked[selectedIPIntel.ip]
                      ? 'bg-rose-500/10 dark:bg-rose-950/50 border-rose-500 text-rose-600 dark:text-rose-400 hover:bg-rose-500/20 shadow-xs'
                      : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800/80 hover:border-slate-300 dark:hover:border-slate-700 hover:text-slate-900 dark:hover:text-white'
                      }`}
                  >
                    {isIPBlocked[selectedIPIntel.ip] ? (
                      <>
                        <Shield className="w-4 h-4 text-rose-500 animate-pulse" />
                        FIREWALL BLOCKED ACTIVE
                      </>
                    ) : (
                      <>
                        <Ban className="w-4 h-4 text-slate-400" />
                        DEPLOY GLOBAL BLACKLIST RULE
                      </>
                    )}
                  </button>
                </div>
              )}

            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};
