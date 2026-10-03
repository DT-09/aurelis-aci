import test from 'node:test'; import assert from 'node:assert/strict'; import {mapProblem} from '../src/core/problem-mapping.mjs';
test('problem mapping identifies data and vendor controls',()=>{const r=mapProblem('We need to control sensitive data sent to a vendor');assert.ok(r.some(x=>x.id==='ai-data-access'));assert.ok(r.some(x=>x.id==='ai-vendor-risk'))});
