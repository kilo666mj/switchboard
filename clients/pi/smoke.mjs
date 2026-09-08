// Read-only live verification; credentials arrive only through the environment.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {ToolListChangedNotificationSchema} from '@modelcontextprotocol/sdk/types.js';
import {Agent,fetch as fetchHTTP} from 'undici';

const endpoint=process.env.SWITCHBOARD_SMOKE_URL;
assert.ok(endpoint,'SWITCHBOARD_SMOKE_URL is required');
const tokenA=process.env.SWITCHBOARD_SMOKE_A_TOKEN,tokenB=process.env.SWITCHBOARD_SMOKE_B_TOKEN;
assert.ok(tokenA && tokenB && tokenA!==tokenB,'two distinct client credentials are required');
const caFile=process.env.SWITCHBOARD_CA_CERTS;
const dispatcher=new Agent(caFile ? {connect:{ca:readFileSync(caFile,'utf8')}} : {});
const fetch=(input,init)=>fetchHTTP(input,{...init,dispatcher});
const opened=[];
async function connect(token){
 const client=new Client({name:'switchboard-rollout-check',version:'1'});
 let changes=0;
 client.setNotificationHandler(ToolListChangedNotificationSchema,()=>{changes++});
 const transport=new StreamableHTTPClientTransport(new URL(endpoint),{requestInit:{headers:{Authorization:`Bearer ${token}`}},fetch});
 await client.connect(transport);opened.push({client,transport});
 return {client,transport,changes:()=>changes};
}
async function tool(client,name,args){return client.callTool({name,arguments:args})}
async function denied(fn){try {const result=await fn();assert.equal(result.isError,true);}catch(error){if(error.code===undefined)throw error;}}
try{
 let response=await fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});assert.equal(response.status,401);await response.body.cancel();
 const a=await connect(tokenA),b=await connect(tokenB);
 assert.ok(a.transport.sessionId && b.transport.sessionId);
 const initial=await a.client.listTools();assert.ok(initial.tools.some(t=>t.name==='wayminder_status'));
 const search=await tool(a.client,'capability_search',{});assert.ok(!search.isError);
 const described=await tool(a.client,'capability_describe',{name:'wayminder'});assert.ok(!described.isError);
 const native=await tool(a.client,'wayminder_status',{});assert.ok(!native.isError);
 const compat=await tool(a.client,'capability_execute',{capability:'wayminder',tool:'wayminder_status',arguments:{}});assert.ok(!compat.isError);
 await denied(()=>tool(a.client,'capability_execute',{capability:'wayminder',tool:'wayminder_forget',arguments:{id:'must-not-be-forwarded'}}));
 await tool(a.client,'capability_enable',{name:'rilldns'});
 const enabled=await a.client.listTools();assert.ok(enabled.tools.some(t=>t.name.startsWith('rilldns_')));
 assert.ok(!(await b.client.listTools()).tools.some(t=>t.name.startsWith('rilldns_')));
 await tool(a.client,'capability_disable',{name:'wayminder'});
 assert.ok(!(await a.client.listTools()).tools.some(t=>t.name==='wayminder_status'));
 await denied(()=>tool(a.client,'wayminder_status',{}));
 await denied(()=>tool(a.client,'capability_execute',{capability:'wayminder',tool:'wayminder_status',arguments:{}}));
 await tool(a.client,'capability_enable',{name:'wayminder'});
 assert.ok(!(await tool(a.client,'wayminder_status',{})).isError);
 const until=Date.now()+3000;while(a.changes()===0&&Date.now()<until)await new Promise(resolve=>setTimeout(resolve,20));assert.ok(a.changes()>0);
 response=await fetch(endpoint,{method:'POST',headers:{Authorization:`Bearer ${tokenB}`,'Mcp-Session-Id':a.transport.sessionId,'Content-Type':'application/json',Accept:'application/json, text/event-stream'},body:JSON.stringify({jsonrpc:'2.0',id:20,method:'tools/list'})});assert.equal(response.status,404);await response.body.cancel();
 const id=a.transport.sessionId;await a.transport.terminateSession();
 response=await fetch(endpoint,{method:'POST',headers:{Authorization:`Bearer ${tokenA}`,'Mcp-Session-Id':id,'Content-Type':'application/json',Accept:'application/json, text/event-stream'},body:JSON.stringify({jsonrpc:'2.0',id:21,method:'tools/list'})});assert.equal(response.status,404);await response.body.cancel();
 console.log(JSON.stringify({authenticated:true,initial_tools:initial.tools.length,enabled_tools:enabled.tools.length,catalog:true,native_read:true,compatibility_read:true,mutation_rejected:true,disabled_execution_rejected:true,notifications:a.changes(),session_isolation:true,identity_isolation:true,deletion:true}));
}finally{
 for(const {client,transport} of opened){try{await transport.terminateSession()}catch{};await client.close()}
 await dispatcher.close();
}
