import { DECISIONS, RISK_LEVELS } from './constants.mjs';

export function classifyRisk(input={}) {
  let score = 0;
  if (input.dataSensitivity === 'RESTRICTED') score += 45;
  else if (input.dataSensitivity === 'CONFIDENTIAL') score += 30;
  else if (input.dataSensitivity === 'INTERNAL') score += 15;
  if (input.destinationTrust === 'EXTERNAL_UNTRUSTED') score += 35;
  else if (input.destinationTrust === 'EXTERNAL_APPROVED') score += 10;
  if (input.actionSeverity === 'CONSEQUENTIAL') score += 25;
  else if (input.actionSeverity === 'MATERIAL') score += 15;
  if (input.identityStatus === 'UNKNOWN') score += 20;
  if (input.approval === 'MISSING') score += 20;
  if (input.vendorRisk === 'HIGH') score += 20;
  if (input.changeDetected) score += 15;
  const level = score >= 85 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 30 ? 'MEDIUM' : 'LOW';
  return { score: Math.min(score,100), level };
}

export function evaluateEvent(input={}) {
  const risk = classifyRisk(input);
  const restrictedExternal = input.dataSensitivity === 'RESTRICTED' && input.destinationTrust !== 'INTERNAL';
  let decision = 'ALLOW';
  let action = 'PROCEED';
  const reasons = [];
  if (restrictedExternal && input.approval !== 'APPROVED') {
    decision = input.approval === 'REQUESTED' ? 'REQUIRE_APPROVAL' : 'DENY';
    action = decision === 'DENY' ? 'BLOCK' : 'HOLD';
    reasons.push('Restricted data is crossing an external boundary without an approved exception.');
  } else if (risk.level === 'CRITICAL') {
    decision = 'ESCALATE'; action = 'CONTAIN'; reasons.push('Critical risk requires human review before consequential action.');
  } else if (risk.level === 'HIGH') {
    decision = 'ALLOW_WITH_CONSTRAINTS'; action = 'CONSTRAIN'; reasons.push('High risk is permitted only with configured constraints.');
  } else {
    reasons.push('No blocking control was triggered by the supplied context.');
  }
  return { decision, action, risk, reasons, engineVersion:'1.0.0' };
}

export function simulatePolicy(events, policy) {
  return events.map(event => {
    const before = evaluateEvent(event);
    const changed = policy?.blockExternalRestricted === true && event.dataSensitivity === 'RESTRICTED' && event.destinationTrust !== 'INTERNAL';
    const after = changed ? { ...before, decision:'DENY', action:'BLOCK', reasons:[...before.reasons,'Simulation policy blocks restricted external transmission.'] } : before;
    return { eventId:event.id, before, after, changed: before.decision !== after.decision || before.action !== after.action };
  });
}

export function decisionIsValid(decision){ return DECISIONS.includes(decision); }
export function riskIsValid(level){ return RISK_LEVELS.includes(level); }
