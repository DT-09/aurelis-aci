import { CAPABILITIES } from './constants.mjs';
const keywordMap = {
  data:['ai-data-access','ai-compliance'], vendor:['ai-vendor-risk','ai-supply-chain'], spend:['ai-spend','ai-observability'], budget:['ai-spend'], incident:['ai-incident','ai-assurance'], recover:['ai-recovery'], model:['ai-supply-chain','ai-assurance'], identity:['ai-identity','ai-trust'], agent:['ai-identity','ai-trust','ai-assurance'], evidence:['ai-compliance','ai-assurance'], audit:['ai-compliance'], production:['ai-assurance','ai-observability'], access:['ai-data-access','ai-identity'], trust:['ai-trust'], observability:['ai-observability']
};
export function mapProblem(text=''){
  const lower=text.toLowerCase(); const ids=new Set();
  for(const [word,caps] of Object.entries(keywordMap)) if(lower.includes(word)) caps.forEach(x=>ids.add(x));
  if(!ids.size) ids.add('ai-assurance');
  return CAPABILITIES.filter(c=>ids.has(c.id));
}
