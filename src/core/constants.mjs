export const CAPABILITIES = [
  { id:'ai-identity', name:'AI Identity', category:'Security & Control', description:'Identity inventory, ownership, authorization and AI actor lifecycle.' },
  { id:'ai-spend', name:'AI Spend Infrastructure', category:'Operations', description:'Spend visibility, budgets, anomaly detection and approval controls.' },
  { id:'ai-incident', name:'AI Incident Infrastructure', category:'Operations', description:'Detection, triage, investigation and containment workflows.' },
  { id:'ai-recovery', name:'AI Recovery Infrastructure', category:'Resilience', description:'Recovery readiness, dependencies, runbooks and recovery evidence.' },
  { id:'ai-supply-chain', name:'AI Supply-Chain Infrastructure', category:'Security & Control', description:'Model, package, tool and dependency provenance and change risk.' },
  { id:'ai-vendor-risk', name:'AI Vendor Risk Infrastructure', category:'Third Party', description:'Vendor inventory, dependency mapping, risk review and monitoring.' },
  { id:'ai-compliance', name:'AI Compliance Evidence Infrastructure', category:'Governance', description:'Control mapping, test results and audit-ready evidence packages.' },
  { id:'ai-data-access', name:'AI Data-Access Control', category:'Data', description:'Sensitive data classification, access decisions and boundary controls.' },
  { id:'ai-trust', name:'AI-to-AI Trust Infrastructure', category:'Security & Control', description:'Agent-to-agent identity, trust, authorization and interaction controls.' },
  { id:'ai-assurance', name:'AI Assurance Infrastructure', category:'Assurance', description:'Assessment, continuous control testing, regression and readiness.' },
  { id:'ai-observability', name:'AI Observability & Business Outcomes Infrastructure', category:'Operations', description:'Operational telemetry, business workflow impact and outcome reporting.' }
];
export const DECISIONS = ['ALLOW','ALLOW_WITH_CONSTRAINTS','DENY','ESCALATE','REQUIRE_APPROVAL'];
export const ASSET_STATES = ['DISCOVERED','ASSESSED','APPROVED','ACTIVE','CHANGED','REASSESSED','RETIRED'];
export const INVESTIGATION_STATES = ['DETECTED','TRIAGED','INVESTIGATING','CONTAINED','REMEDIATING','RETESTING','RESOLVED'];
export const REMEDIATION_STATES = ['OPEN','ASSIGNED','REMEDIATING','RETESTING','PASSED','RESOLVED'];
export const RISK_LEVELS = ['LOW','MEDIUM','HIGH','CRITICAL'];
