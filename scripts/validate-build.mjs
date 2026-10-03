import fs from 'node:fs'; import path from 'node:path';
const root=process.cwd();
const required=['package.json','wrangler.toml','db/schema.sql','public/index.html','public/demo.html','public/access.html','public/workspace.html','public/admin.html','functions/api/[[path]].mjs','functions/_middleware.mjs','src/core/control-engine.mjs'];
const missing=required.filter(f=>!fs.existsSync(path.join(root,f))); if(missing.length){console.error('Missing:',missing);process.exit(1)}
const html=fs.readFileSync(path.join(root,'public/index.html'),'utf8'); if(!html.includes('AURELIS ACI')) throw new Error('Brand missing');
const domains=['ai-identity','ai-spend','ai-incident','ai-recovery','ai-supply-chain','ai-vendor-risk','ai-compliance','ai-data-access','ai-trust','ai-assurance','ai-observability'];
const c=fs.readFileSync(path.join(root,'src/core/constants.mjs'),'utf8'); for(const d of domains) if(!c.includes(d)) throw new Error(`Capability missing: ${d}`);
console.log(`Build validation passed: ${required.length} required files; ${domains.length} initial capabilities.`);
