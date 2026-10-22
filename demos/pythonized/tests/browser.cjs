const { chromium }=require('playwright');
const fs=require('node:fs');const path=require('node:path');const assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..');fs.mkdirSync(path.join(root,'artifacts'),{recursive:true});
(async()=>{const browser=await chromium.launch();
for(const [name,width,height] of [['laptop',1440,900],['stage',1920,1080],['mobile',390,844]]){
 const page=await browser.newPage({viewport:{width,height},reducedMotion:'reduce'});const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://127.0.0.1:5184');await page.waitForFunction(()=>document.querySelector('#theatre').dataset.permission!==undefined);
 for(let i=0;i<7;i++){await page.goto(`http://127.0.0.1:5184/#${i}`);await page.locator(`[data-scene="${i}"]`).waitFor({state:'visible'});await page.evaluate(async()=>{await Promise.all([...document.images].map(im=>im.decode().catch(()=>{})))});await page.screenshot({path:path.join(root,`artifacts/${name}-${i}.png`),fullPage:true});const sideways=await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+2);assert(!sideways,`${name} scene ${i} has horizontal overflow`);if(name!=='mobile'){const clip=await page.locator(`[data-scene="${i}"]`).evaluate(el=>({height:el.scrollHeight-el.clientHeight,width:el.scrollWidth-el.clientWidth}));assert(clip.height<=3,`${name} scene ${i} clipped vertically: ${clip.height}`);}}
 assert.deepEqual(errors,[]);await page.close();
}
const p=await browser.newPage({viewport:{width:1440,height:900}});await p.goto('http://127.0.0.1:5184/#1');
async function click(action){const response=p.waitForResponse(r=>r.url().endsWith('/api/action'));await p.locator(`[data-scene]:not([hidden]) [data-action="${action}"],.source-bar [data-action="${action}"]`).click();return (await response).json();}
await click('reset');for(let i=0;i<3;i++)await click('shadow');let s=await click('qualify');assert.equal(s.qualification.disposition,'ELIGIBLE');assert.equal(Object.keys(s.authority.grants).length,0);
await p.goto('http://127.0.0.1:5184/#2');s=await click('grant');assert(s.authority.grants['release-model']);
await p.goto('http://127.0.0.1:5184/#3');await click('admit');await click('revoke');s=await click('commit');assert.equal(s.last.ok,false);assert.equal(s.mutations,0);
await p.goto('http://127.0.0.1:5184/#1');await click('reset');for(let i=0;i<3;i++)await click('shadow');await click('qualify');await p.goto('http://127.0.0.1:5184/#2');await click('grant');
await p.goto('http://127.0.0.1:5184/#5');await click('read_grant');await p.goto('http://127.0.0.1:5184/#3');await click('admit');await p.locator('#wrong-result').check();s=await click('commit');assert.equal(s.execution.outcome.outcome,'FAIL');await p.goto('http://127.0.0.1:5184/#5');s=await click('apply');assert(!s.authority.grants['release-model']);assert(s.authority.grants['read-health']);s=await click('read_skill');assert.equal(s.last.ok,true);s=await click('requalify');assert.equal(s.version,'skill-v2');assert(!s.authority.grants['release-model']);s=await click('grant');assert.equal(s.authority.grants['release-model'].version,'skill-v2');
const count=s.mutations,actions=s.actions.length;await p.locator('#replay').click();await p.locator('#pause').click();assert(await p.locator('#theatre').evaluate(el=>el.classList.contains('paused')));const after=await (await p.request.get('http://127.0.0.1:5184/api/state')).json();assert.equal(after.mutations,count);assert.equal(after.actions.length,actions);
await p.goto('http://127.0.0.1:5184/#6');await p.locator('#roadmap-load').click();await p.waitForFunction(()=>document.querySelector('#roadmap-status').textContent==='AMBER');
await p.goto('http://127.0.0.1:5184/#0');await p.screenshot({path:path.join(root,'artifacts/cover-motion.png')});
await browser.close();console.log('All three viewport reviews and the complete local-runtime lifecycle passed.');})().catch(e=>{console.error(e);process.exit(1)});
