import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import https from 'node:https';
import { once } from 'node:events';
import { createJiti } from 'jiti';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';

const jiti = createJiti(import.meta.url);
const extension = await jiti.import('./index.ts', { default: true });
const eventually = async predicate => {
  const deadline = Date.now() + 3000;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error('tool refresh did not arrive');
    await new Promise(resolve => setTimeout(resolve, 10));
  }
};

test('pi discovers, refreshes, preserves results, and confirms mutations', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'switchboard-pi-'));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1', '-keyout', join(dir,'key.pem'), '-out', join(dir,'ca.pem')], { stdio: 'ignore' });
  const server = new Server({name:'fixture',version:'test'}, {capabilities:{tools:{listChanged:true}}});
  const read = {name:'demo_read',description:'Read fixture',inputSchema:{type:'object'},annotations:{readOnlyHint:true,destructiveHint:false}};
  const mutate = {name:'demo_mutate',description:'Mutate fixture',inputSchema:{type:'object'},annotations:{readOnlyHint:false}};
  let tools = [read]; let calls = 0; let failListing=false;let blockListing=false,releaseListing;let blockDelete=false,deleteReceived=false;
  server.setRequestHandler(ListToolsRequestSchema, async () => {if(failListing)throw new Error('synthetic-private-catalog-error');const snapshot=tools;if(blockListing){blockListing=false;await new Promise(resolve=>releaseListing=resolve);}return {tools:snapshot};});
  server.setRequestHandler(CallToolRequestSchema, async () => {
    calls++;
    return {content:[{type:'text',text:'ok'}],structuredContent:{ok:true}};
  });
  const transport = new StreamableHTTPServerTransport({sessionIdGenerator:()=> 'test-session'});
  await server.connect(transport);
  const http = https.createServer({key:readFileSync(join(dir,'key.pem')),cert:readFileSync(join(dir,'ca.pem'))}, async (req,res) => {
    if (req.headers.authorization !== 'Bearer test-token') {res.writeHead(401).end();return;}
    if(req.method==='DELETE'&&blockDelete){deleteReceived=true;return;}
    const body=[];for await (const chunk of req) body.push(chunk);
    await transport.handleRequest(req,res,body.length ? JSON.parse(Buffer.concat(body)) : undefined);
  });
  let connections=0;http.on('connection',()=>connections++);
  http.listen(0,'127.0.0.1');await once(http,'listening');
  const config=join(dir,'config.json');writeFileSync(config,JSON.stringify({url:`https://127.0.0.1:${http.address().port}/mcp`,token_env:'SWITCHBOARD_PI_TEST_TOKEN'}));
  process.env.SWITCHBOARD_PI_CONFIG=config;process.env.SWITCHBOARD_CA_CERTS=join(dir,'ca.pem');process.env.SWITCHBOARD_PI_TEST_TOKEN='test-token';
  const events=new Map(), definitions=new Map();let active=['builtin_read'];let consent=false;const notices=[];const activationHistory=[];
  const pi={on:(name,handler)=>events.set(name,handler),registerTool:tool=>definitions.set(tool.name,tool),getActiveTools:()=>active,setActiveTools:names=>{active=names;activationHistory.push([...names])}};
  const ctx={hasUI:true,ui:{confirm:async()=>consent,notify:message=>notices.push(message)}};
  extension(pi);
  try {
    const emptyCA=join(dir,'empty-ca.pem');writeFileSync(emptyCA,'');
    for(const invalidCA of [join(dir,'missing-private-ca.pem'),emptyCA,dir,'']){
      process.env.SWITCHBOARD_CA_CERTS=invalidCA;
      await events.get('session_start')({},ctx);
      assert.equal(connections,0,'invalid explicit CA fell back to another trust store');
      assert.deepEqual(active,['builtin_read']);
      assert.deepEqual(notices,['Switchboard connection failed; check URL, credentials, and CA trust']);
      notices.length=0;
    }
    process.env.SWITCHBOARD_CA_CERTS=join(dir,'ca.pem');
    await events.get('session_start')({},ctx);
    assert.deepEqual(notices,[]);assert.ok(active.includes('demo_read'));assert.ok(active.includes('builtin_read'));
    const staleRead=definitions.get('demo_read');
    failListing=true;await server.sendToolListChanged();await eventually(()=>notices.length>0);
    assert.deepEqual(active,['builtin_read']);
    await assert.rejects(()=>staleRead.execute('stale',{},undefined,undefined,ctx),/no longer active/);
    assert.equal(calls,0);assert.ok(!notices.join(' ').includes('synthetic-private-catalog-error'));
    failListing=false;await server.sendToolListChanged();await eventually(()=>active.includes('demo_read'));
    assert.ok(active.includes('builtin_read'));
    blockListing=true;await server.sendToolListChanged();await eventually(()=>Boolean(releaseListing));
    activationHistory.length=0;
    tools=[mutate];await server.sendToolListChanged();
    // Wait until the second notification has invalidated the still-pending list.
    await eventually(()=>activationHistory.length>0);
    releaseListing();await eventually(()=>active.includes('demo_mutate'));
    assert.ok(activationHistory.every(names=>!names.includes('demo_read')),'stale list briefly reactivated an obsolete tool');
    tools=[read];await server.sendToolListChanged();await eventually(()=>active.includes('demo_read'));
    const result=await definitions.get('demo_read').execute('1',{},new AbortController().signal,undefined,ctx);
    assert.deepEqual(result.details,{structuredContent:{ok:true}});assert.equal(calls,1);
    tools=[read,mutate];await server.sendToolListChanged();await eventually(()=>active.includes('demo_mutate'));
    await assert.rejects(()=>definitions.get('demo_mutate').execute('2',{},undefined,undefined,ctx),/requires approval/);assert.equal(calls,1);
    consent=true;await definitions.get('demo_mutate').execute('3',{},undefined,undefined,ctx);assert.equal(calls,2);
    // A pending approval cannot survive removal and reactivation of the same
    // name, or replacement of the tool metadata while the dialog is open.
    for (const reactivate of [false, true]) {
      let approve;
      const waitingContext={hasUI:true,ui:{...ctx.ui,confirm:()=>new Promise(resolve=>approve=resolve)}};
      const pending=definitions.get('demo_mutate').execute('pending',{},undefined,undefined,waitingContext);
      const rejected=assert.rejects(()=>pending,/no longer active/);
      await eventually(()=>Boolean(approve));
      tools=[read];await server.sendToolListChanged();await eventually(()=>!active.includes('demo_mutate'));
      if(reactivate){tools=[read,{...mutate,description:'Changed synthetic mutation'}];await server.sendToolListChanged();await eventually(()=>active.includes('demo_mutate'));}
      approve(true);await rejected;assert.equal(calls,2);
      tools=[read,mutate];await server.sendToolListChanged();await eventually(()=>active.includes('demo_mutate'));
    }
    tools=[mutate];await server.sendToolListChanged();await eventually(()=>!active.includes('demo_read'));
    await assert.rejects(()=>definitions.get('demo_read').execute('4',{},undefined,undefined,ctx),/no longer active/);assert.equal(calls,2);
    blockDelete=true;
    const shutdownStarted=Date.now();
    await events.get('session_shutdown')();
    assert.ok(deleteReceived,'session DELETE not attempted');
    assert.ok(Date.now()-shutdownStarted<5000,'stalled gateway blocked shutdown');
    assert.deepEqual(active,['builtin_read']);
    await assert.rejects(()=>definitions.get('demo_mutate').execute('after-shutdown',{},undefined,undefined,ctx),/no longer active/);
    assert.equal(calls,2);
    // The finally handler invokes shutdown again to verify idempotent cleanup.

  } finally {
    await events.get('session_shutdown')();await server.close();http.closeAllConnections();await new Promise(resolve=>http.close(resolve));
    for(const key of ['SWITCHBOARD_PI_CONFIG','SWITCHBOARD_CA_CERTS','SWITCHBOARD_PI_TEST_TOKEN']) delete process.env[key];
    rmSync(dir,{recursive:true,force:true});
  }
});
