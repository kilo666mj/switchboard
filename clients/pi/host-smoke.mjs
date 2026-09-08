// Opt-in installed pi host check. Only a temporary HTTPS MCP fixture is contacted.
import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, writeFileSync, mkdirSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, isAbsolute} from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync, spawn} from 'node:child_process';
import https from 'node:https';
import httpModule from 'node:http';
import {once} from 'node:events';
import {createInterface} from 'node:readline';
import {Server} from '@modelcontextprotocol/sdk/server/index.js';
import {StreamableHTTPServerTransport} from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {ListToolsRequestSchema, CallToolRequestSchema} from '@modelcontextprotocol/sdk/types.js';

const execute = process.argv.includes('--execute');
const binary = process.env.SWITCHBOARD_PI_BINARY;
assert.ok(binary && isAbsolute(binary), 'Set SWITCHBOARD_PI_BINARY to the installed absolute pi executable');
const dir = mkdtempSync(join(tmpdir(), 'switchboard-pi-host-'));
const home=join(dir,'home');mkdirSync(home);
execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=synthetic-gateway','-addext','subjectAltName=IP:127.0.0.1','-keyout',join(dir,'key.pem'),'-out',join(dir,'ca.pem')],{stdio:'ignore'});
const server=new Server({name:'synthetic-gateway',version:'1'},{capabilities:{tools:{listChanged:true}}});
const read={name:'demo_read',description:'Read synthetic data',inputSchema:{type:'object',properties:{}},annotations:{readOnlyHint:true,destructiveHint:false}};
const mutate={name:'demo_mutate',description:'Synthetic mutation',inputSchema:{type:'object',properties:{}},annotations:{readOnlyHint:false}};
let tools=[read], calls=0, authenticated=0;
server.setRequestHandler(ListToolsRequestSchema,async()=>({tools}));
server.setRequestHandler(CallToolRequestSchema,async()=>{calls++;return {content:[{type:'text',text:'synthetic'}],structuredContent:{verified:true}};});
const transport=new StreamableHTTPServerTransport({sessionIdGenerator:()=> 'synthetic-session'});
await server.connect(transport);
const http=https.createServer({key:readFileSync(join(dir,'key.pem')),cert:readFileSync(join(dir,'ca.pem'))},async(req,res)=>{
 if(req.headers.authorization!=='Bearer synthetic-host-token'){res.writeHead(401).end();return;}
 authenticated++;
 const body=[];for await(const part of req)body.push(part);
 await transport.handleRequest(req,res,body.length?JSON.parse(Buffer.concat(body)):undefined);
});
http.listen(0,'127.0.0.1');await once(http,'listening');
writeFileSync(join(dir,'config.json'),JSON.stringify({url:`https://127.0.0.1:${http.address().port}/mcp`,token_env:'SWITCHBOARD_PI_TEST_TOKEN'}));
// A second real extension observes the host's public tool registry. It does
// not replace registerTool, active-tool state or session lifecycle callbacks.
const observer=join(dir,'observer.ts');
writeFileSync(observer,`export default function(pi) {
 pi.registerCommand('synthetic-tool-probe', {description:'Inspect test tool registry', handler:async(_args,ctx)=> {
  ctx.ui.notify(JSON.stringify({type:'synthetic_tool_probe',active:pi.getActiveTools(),tools:pi.getAllTools().map(t=>({name:t.name,parameters:t.parameters}))}),'info');
 }});
}`);
let modelCalls=0, modelResults=[];
const modelServer=httpModule.createServer(async(req,res)=>{
 if(req.url!=='/v1/chat/completions'||req.headers.authorization!=='Bearer synthetic-model-key'){res.writeHead(400).end();return;}
 const parts=[];for await(const part of req)parts.push(part);
 const request=JSON.parse(Buffer.concat(parts));modelCalls++;
 const last=request.messages.at(-1);
 const user=request.messages.findLast(m=>m.role==='user');
 const content=typeof user?.content==='string'?user.content:JSON.stringify(user?.content);
 const tool=content.includes('synthetic-read')?'demo_read':'demo_mutate';
 const final=last.role==='tool';
 if(final)modelResults.push(last.content);
 const delta=final?{role:'assistant',content:'Synthetic pi execution complete.'}:{role:'assistant',tool_calls:[{index:0,id:'synthetic_call_'+modelCalls,type:'function',function:{name:tool,arguments:'{}'}}]};
 res.writeHead(200,{'Content-Type':'text/event-stream'});
 for(const [value,finish] of [[delta,null],[{},final?'stop':'tool_calls']])res.write('data: '+JSON.stringify({id:'synthetic_completion',object:'chat.completion.chunk',created:1,model:'synthetic-model',choices:[{index:0,delta:value,finish_reason:finish}]})+'\n\n');
 res.end('data: [DONE]\n\n');
});
if(execute){
 modelServer.listen(0,'127.0.0.1');await once(modelServer,'listening');
 const agentDir=join(home,'.pi/agent');mkdirSync(agentDir,{recursive:true});
 writeFileSync(join(agentDir,'models.json'),JSON.stringify({providers:{synthetic:{baseUrl:`http://127.0.0.1:${modelServer.address().port}/v1`,api:'openai-completions',apiKey:'synthetic-model-key',models:[{id:'synthetic-model',reasoning:false,input:['text'],contextWindow:32000,maxTokens:1000,cost:{input:0,output:0,cacheRead:0,cacheWrite:0}}]}}}));
}
let child, lines;
try {
 child=spawn(binary,['--mode','rpc','--no-session','--no-extensions','--no-skills','--no-prompt-templates','-e',fileURLToPath(new URL('./index.ts',import.meta.url)),'-e',observer,...(execute?['--provider','synthetic','--model','synthetic-model']:[])],{
  cwd:dir,env:{PATH:process.env.PATH,HOME:home,PI_CODING_AGENT_DIR:join(home,'.pi/agent'),LANG:'C.UTF-8',SWITCHBOARD_PI_CONFIG:join(dir,'config.json'),SWITCHBOARD_CA_CERTS:join(dir,'ca.pem'),SWITCHBOARD_PI_TEST_TOKEN:'synthetic-host-token'},stdio:['pipe','pipe','pipe']
 });
 child.stderr.on('data',()=>{}); // No host diagnostics or private content printed.
 let exited=false, probe, failure, consent=false, confirmations=0, settled=0, ready=false; const notifications=[]; const toolEnds=[];
 child.on('exit',()=>{exited=true});child.on('error',()=>{failure='pi process could not start'});
 lines=createInterface({input:child.stdout});
 lines.on('line',line=>{try {
  const message=JSON.parse(line);
  if(message.type==='response'&&message.command==='get_state'&&message.success===true)ready=true;
  if(message.type==='agent_settled')settled++;
  if(message.type==='tool_execution_end')toolEnds.push(message);
  if(message.type==='extension_ui_request'&&message.method==='confirm'){
   confirmations++;child.stdin.write(JSON.stringify({type:'extension_ui_response',id:message.id,confirmed:consent})+'\n');
  }
  if(message.type==='extension_ui_request'&&message.method==='notify'){
   let value;try{value=JSON.parse(message.message);}catch{notifications.push(message.message);return;}if(value.type==='synthetic_tool_probe')probe=value;
  }
 }catch{}});

 const inspect=async(predicate)=>{
  const deadline=Date.now()+15000;
  while(Date.now()<deadline){
   assert.ok(!exited&&!failure,failure??'pi process exited before verification');
   child.stdin.write(JSON.stringify({type:'prompt',message:'/synthetic-tool-probe'})+'\n');
   await new Promise(resolve=>setTimeout(resolve,150));
   if(probe&&predicate(probe))return probe;
  }
  throw new Error('installed pi tool registry missing: '+JSON.stringify({authenticated,active:probe?.active,notifications}));
 };
 // Wait for the actual RPC host to finish startup before issuing extension
 // commands; buffering commands during extension loading is not a readiness check.
 child.stdin.write(JSON.stringify({type:'get_state'})+'\n');
 const startupDeadline=Date.now()+30000;
 while(!ready&&!exited&&!failure&&Date.now()<startupDeadline)await new Promise(resolve=>setTimeout(resolve,50));
 assert.ok(ready&&!exited&&!failure,'installed pi RPC startup did not complete');
 const initial=await inspect(p=>p.active.includes('demo_read'));
 const builtins=initial.active.filter(name=>!name.startsWith('demo_'));
 assert.ok(builtins.includes('read'),'pi builtin tools not present');
 assert.equal(initial.tools.find(t=>t.name==='demo_read').parameters.type,'object');
 tools=[read,mutate];await server.sendToolListChanged();
 await inspect(p=>p.active.includes('demo_mutate'));
 tools=[mutate];await server.sendToolListChanged();
 const updated=await inspect(p=>!p.active.includes('demo_read')&&p.active.includes('demo_mutate'));
 assert.ok(builtins.every(name=>updated.active.includes(name)),'adapter removed host tools');
 assert.ok(authenticated>0);assert.equal(calls,0,'registry probe unexpectedly executed an upstream tool');
 if(execute){
  tools=[read,mutate];await server.sendToolListChanged();await inspect(p=>p.active.includes('demo_read'));
  for(const [prompt,allowed,expectedCalls,expectedConfirms] of [['synthetic-read',false,1,0],['synthetic-deny',false,1,1],['synthetic-approve',true,2,2]]){
   consent=allowed;const before=settled,previousTools=toolEnds.length;
   child.stdin.write(JSON.stringify({type:'prompt',message:prompt})+'\n');
   const deadline=Date.now()+15000;
   while(settled===before&&Date.now()<deadline&&!exited)await new Promise(resolve=>setTimeout(resolve,50));
   assert.ok(settled>before,'synthetic model turn did not settle');
   assert.equal(calls,expectedCalls,'unexpected upstream call count');
   assert.equal(confirmations,expectedConfirms,'wrong native approval flow');
   assert.equal(toolEnds.length,previousTools+1,'missing native tool execution result');
   const ended=toolEnds.at(-1);
   assert.equal(Boolean(ended.isError),prompt==='synthetic-deny');
   if(prompt!=='synthetic-deny')assert.deepEqual(ended.result.details,{structuredContent:{verified:true}});
  }
  assert.equal(modelCalls,6,'unexpected model request count');
  assert.equal(modelResults.length,3);
  assert.ok(JSON.stringify(modelResults[1]).includes('requires approval'),'denied result missing from model context');
 }

 console.log(JSON.stringify({installed_pi_extension_loaded:true,native_tool_registry:true,tool_schema_preserved:true,live_tool_refresh:true,builtin_tools_preserved:true,upstream_tool_calls:calls,synthetic_model_calls:modelCalls,native_approval_checked:execute,real_model_calls:0}));
} finally {
 lines?.close();
 if(child&&child.exitCode===null&&child.signalCode===null){
  child.kill('SIGTERM');
  await Promise.race([once(child,'exit'),new Promise(resolve=>setTimeout(resolve,3000))]);
  if(child.exitCode===null&&child.signalCode===null){child.kill('SIGKILL');await once(child,'exit');}
 }
 if(execute){modelServer.closeAllConnections();await new Promise(resolve=>modelServer.close(resolve));}
 await server.close();http.closeAllConnections();await new Promise(resolve=>http.close(resolve));
 rmSync(dir,{recursive:true,force:true});
}
