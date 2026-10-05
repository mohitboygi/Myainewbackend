/* Mohit AI backend. Keys/settings go in config.js next to this file. */

import express,{Router} from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Database from "better-sqlite3";
import {parsePhoneNumberFromString} from "libphonenumber-js";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";

const dir=path.dirname(fileURLToPath(import.meta.url));
// Settings: config.js (optional) + hosting dashboard variables (these win if both are set)
const config=await import("./config.js").then(m=>m.default).catch(()=>({}));
for(const[k,v]of Object.entries(config)){const x=Array.isArray(v)?v.filter(Boolean).join(","):String(v??"");if(x!==""&&!process.env[k])process.env[k]=x}
const E=process.env;
const wrap=fn=>(q,s,n)=>Promise.resolve().then(()=>fn(q,s)).catch(n);
const sha=x=>crypto.createHash("sha256").update(x).digest("hex");
const httpErr=(status,message)=>Object.assign(new Error(message),{status});

/* ================= DATABASE ================= */
const db=new Database(process.env.DB_PATH||"./data.db");
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,name TEXT NOT NULL,phone TEXT UNIQUE NOT NULL,pw_hash TEXT NOT NULL,verified INTEGER NOT NULL DEFAULT 0,created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS otp_sessions(phone TEXT PRIMARY KEY,logid TEXT,code_hash TEXT,expires_at INTEGER NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,last_sent INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS otp_sends(phone TEXT NOT NULL,at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS i_sends ON otp_sends(phone,at);`);
db.exec(`
CREATE TABLE IF NOT EXISTS api_keys(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL,name TEXT NOT NULL,prefix TEXT NOT NULL,key_hash TEXT UNIQUE NOT NULL,created_at INTEGER NOT NULL,last_used INTEGER,revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS usage(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL,key_id INTEGER,at INTEGER NOT NULL,source TEXT NOT NULL,tier TEXT,provider TEXT,model TEXT,prompt_tokens INTEGER NOT NULL DEFAULT 0,completion_tokens INTEGER NOT NULL DEFAULT 0,total_tokens INTEGER NOT NULL DEFAULT 0,estimated INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS i_use_u ON usage(user_id,at);CREATE INDEX IF NOT EXISTS i_use_k ON usage(key_id);`);
for(const c of["monthly_quota INTEGER","disabled INTEGER NOT NULL DEFAULT 0"])try{db.exec("ALTER TABLE users ADD COLUMN "+c)}catch{}

/* ================= BRAND FILTER (always answers as Mohit AI) ================= */
/* Brand identity filter: whoever asks, the answer is "Mohit AI, a model by Mohit Corporation" */
const VENDORS=/\b(open\s?ai|chat\s?gpt|gpt-?\d[\w.-]*|anthropic|claude|gemini|google|bard|meta|llama|mistral|mixtral|codestral|pixtral|magistral|groq|samba\s?nova|deepseek|qwen|alibaba|bynara|tokenin|microsoft|copilot|xai|grok)\b/i;
const FIRST=/\b(i am|i'm|i was|i've been|my (name|model|creator|developer|maker|architecture)|main (hoon|hun))\b/i;
const CLAIM=/\b(model|assistant|chatbot|trained|created|developed|built|made|powered|based on|creator|developer)\b/i;

const IDENTITY=[
  /\b(who|which company|what company|which organi[sz]ation)\b.{0,30}\b(made|make|makes|making|creat\w*|built|build\w*|train\w*|develop\w*|own\w*|design\w*|program\w*|invent\w*|behind)\b.{0,20}\b(you|u|this|it|the (ai|model|bot|app|assistant))\b/i,
  /\bwho are (you|u)\b|\bwhat are (you|u)\b|\bwhat('?s| is) your (name|model|version|architecture)\b|\b(introduce|tell me about) (yourself|urself)\b/i,
  /\b(which|what)\b.{0,20}\b(model|llm|ai|gpt|engine|architecture|version|company)\b.{0,25}\b(are you|are u|is this|is it|you use|you are|do you use|powering|behind)\b/i,
  /\b(are|r) (you|u)\b.{0,30}\b(chat\s?gpt|gpt|openai|claude|gemini|llama|mistral|grok|deepseek|qwen|bard|copilot|meta|google|anthropic|groq)\b/i,
  /\b(are|r) (you|u)\b.{0,25}\b(built|based|powered|running|trained)\b/i,
  /\b(your|ur)\b.{0,12}\b(creator|developer|maker|company|owner|founder)\b/i,
  /kis\s*ne\s+(banaya|bnaya|banai|develop|train|bnai)|kisne\s+(banaya|bnaya|banai|develop|train|bnai)|(tum|tu|aap|tumhe|tujhe|apko|aapko)\b.{0,20}\b(kisne|kon|kaun|kaunsa|konsa)\b|(tera|tumhara|aapka|tmhara)\b.{0,12}\b(naam|name|model|company|creator|owner|malik|developer)\b|kaun\s+(ho|hai|hain)\s*(tum|tu|aap)?|(kaun|kon|kaunsa|konsa)\s*(sa\s*)?(model|ai|company)\b|kis\s*(company|ka\s+(model|ai))\b|(tum|tu|aap)\b.{0,15}\b(chat\s?gpt|gpt|llama|claude|gemini|mistral)\b.{0,10}\b(ho|hai|hain)\b|तुम्?हे?\s*किसने|तुम\s*कौन|आप\s*कौन|किस\s*ने|किसने|कौन\s*सा\s*मॉडल/i
];
const HINGLISH=/[\u0900-\u097F]|kisne|kis\s*ne|\bkis\b|kaun|kon\b|konsa|kaunsa|\btum\b|\btu\b|tera|tumhara|aap|banaya|naam|tujhe|tumhe|\bkya\b|\bho\b|\bhai\b|malik/i;

/* Returns a ready reply for short identity questions, otherwise null (no model call needed) */
function identityReply(text){
  const t=String(text||"").trim();
  if(!t||t.length>200||!IDENTITY.some(r=>r.test(t)))return null;
  return HINGLISH.test(t)?"Main Mohit AI hoon, Mohit Corporation ka model.":"I'm Mohit AI, a model by Mohit Corporation.";
}

const fix=s=>s.split(/(?<=[.!?]\s)|(?<=\n)/).map(x=>VENDORS.test(x)&&FIRST.test(x)&&CLAIM.test(x)?"I'm Mohit AI, a model by Mohit Corporation."+(x.match(/\s*$/)[0]||" "):x).join("");
const cut=b=>{let i=-1,m;const r=/[.!?]\s|\n/g;while((m=r.exec(b)))i=m.index+m[0].length;return i};

/* Wraps the model's text stream: rewrites sentences where the model names another company/model as itself */
async function* brand(it){
  let b="";
  for await(const t of it){
    b+=t;const i=cut(b);
    if(i>0){yield fix(b.slice(0,i));b=b.slice(i)}
    else if(b.length>400){yield fix(b);b=""}
  }
  if(b)yield fix(b);
}

/* ================= OTP (Authkey) ================= */
const AK=E.AUTHKEY,SID=E.AUTHKEY_SID;
const MODE=E.OTP_MODE||(AK?"authkey":"console");
const TTL=+(E.OTP_TTL_SECONDS||300)*1000,RESEND=+(E.OTP_RESEND_SECONDS||30)*1000,PER_HOUR=+(E.OTP_MAX_PER_HOUR||5),MAX_TRY=+(E.OTP_MAX_ATTEMPTS||5);
if(MODE==="authkey"&&(!AK||!SID))throw new Error("AUTHKEY and AUTHKEY_SID are required");
if(MODE==="console"&&E.NODE_ENV==="production")throw new Error("OTP_MODE=console is not allowed in production. Set AUTHKEY + AUTHKEY_SID.");

async function sendOtp({e164,cc,national}){
  const now=Date.now(),s=db.prepare("SELECT * FROM otp_sessions WHERE phone=?").get(e164);
  if(s&&now-s.last_sent<RESEND)throw httpErr(429,`Wait ${Math.ceil((RESEND-(now-s.last_sent))/1000)}s before requesting another code.`);
  db.prepare("DELETE FROM otp_sends WHERE at<?").run(now-3600e3);
  if(db.prepare("SELECT COUNT(*) c FROM otp_sends WHERE phone=?").get(e164).c>=PER_HOUR)throw httpErr(429,"Too many codes requested. Try again in an hour.");
  let logid=null,codeHash=null;
  if(MODE==="authkey"){
    const u=new URL("https://api.authkey.io/request");
    u.search=new URLSearchParams({authkey:AK,mobile:national,country_code:cc,sid:SID});
    const r=await fetch(u,{signal:AbortSignal.timeout(10000)}).catch(()=>null);
    const j=r&&await r.json().catch(()=>null);
    logid=j&&(j.LogID||j.logid||j.logID||j.Logid);
    if(!r||!r.ok||!logid){console.error("[otp] authkey send failed",r&&r.status,JSON.stringify(j));throw httpErr(502,"Couldn't send the code. Try again shortly.")}
  }else{
    const code=String(crypto.randomInt(0,1e6)).padStart(6,"0");codeHash=sha(code);console.log(`[DEV OTP] ${e164}: ${code}`);
  }
  db.prepare("INSERT INTO otp_sessions(phone,logid,code_hash,expires_at,attempts,last_sent) VALUES(?,?,?,?,0,?) ON CONFLICT(phone) DO UPDATE SET logid=excluded.logid,code_hash=excluded.code_hash,expires_at=excluded.expires_at,attempts=0,last_sent=excluded.last_sent").run(e164,logid,codeHash,now+TTL,now);
  db.prepare("INSERT INTO otp_sends(phone,at) VALUES(?,?)").run(e164,now);
}

async function verifyOtp(e164,code){
  const s=db.prepare("SELECT * FROM otp_sessions WHERE phone=?").get(e164),del=()=>db.prepare("DELETE FROM otp_sessions WHERE phone=?").run(e164);
  if(!s)throw httpErr(400,"No active code. Request a new one.");
  if(Date.now()>s.expires_at){del();throw httpErr(400,"Code expired. Request a new one.")}
  if(s.attempts>=MAX_TRY){del();throw httpErr(429,"Too many wrong attempts. Request a new code.")}
  db.prepare("UPDATE otp_sessions SET attempts=attempts+1 WHERE phone=?").run(e164);
  let ok=false;
  if(MODE==="authkey"){
    const u=new URL("https://console.authkey.io/restapi/2fa_verify.php");
    u.search=new URLSearchParams({authkey:AK,channel:"SMS",otp:code,logid:s.logid});
    const r=await fetch(u,{signal:AbortSignal.timeout(10000)}).catch(()=>null);
    if(!r)throw httpErr(502,"Couldn't verify the code. Try again shortly.");
    const t=await r.text();ok=/valid otp/i.test(t)&&!/invalid/i.test(t);
  }else{
    const a=Buffer.from(sha(code)),b=Buffer.from(s.code_hash);ok=a.length===b.length&&crypto.timingSafeEqual(a,b);
  }
  if(!ok)throw httpErr(400,"That code isn't right. Check it and try again.");
  del();
}

/* ================= AI ROUTER + PROVIDER KEYS (read from config.js) ================= */
const keys=n=>(E[n]||"").split(",").map(s=>s.trim()).filter(Boolean);
const ALL={
  groq:{base:"https://api.groq.com/openai/v1",keys:keys("GROQ_KEYS")},
  mistral:{base:"https://api.mistral.ai/v1",keys:keys("MISTRAL_KEYS")},
  sambanova:{base:"https://api.sambanova.ai/v1",keys:keys("SAMBANOVA_KEYS")},
  tokenin:{base:E.TOKENIN_BASE_URL||"https://tokenin.my.id/v1",keys:keys("TOKENIN_KEYS")},
  bynara:{base:E.BYNARA_BASE_URL||"",keys:keys("BYNARA_KEYS")},
  custom:{base:E.CUSTOM_BASE_URL||"",keys:keys("CUSTOM_KEYS")}};
const P=Object.fromEntries(Object.entries(ALL).filter(([,v])=>v.base&&v.keys.length).map(([k,v])=>[k,{...v,base:v.base.replace(/\/$/,"")}]));
for(const[k,v]of Object.entries(ALL))if(v.keys.length&&!v.base)console.warn(`[router] ${k}: keys found but ${k.toUpperCase()}_BASE_URL is missing, so ${k} is skipped`);
// Default model IDs change over time: check each provider's model list and override via <PROVIDER>_MODEL_<TIER> in .env
const DEF={
  groq:{fast:"llama-3.1-8b-instant",smart:"llama-3.3-70b-versatile",coding:"llama-3.3-70b-versatile",reasoning:"qwen/qwen3-32b",vision:"meta-llama/llama-4-scout-17b-16e-instruct"},
  mistral:{fast:"mistral-small-latest",smart:"mistral-large-latest",coding:"codestral-latest",reasoning:"magistral-medium-latest",vision:"pixtral-large-latest"},
  sambanova:{fast:"Meta-Llama-3.1-8B-Instruct",smart:"Meta-Llama-3.3-70B-Instruct",coding:"Meta-Llama-3.3-70B-Instruct",reasoning:"DeepSeek-R1",vision:"Llama-4-Maverick-17B-128E-Instruct"}};
const ORDER=E.ROUTE_ORDER||"custom,groq,mistral,sambanova,tokenin,bynara";
const TIERS=["fast","smart","coding","reasoning","vision"];
const SYSTEM="You are Mohit AI, a model by Mohit Corporation. If anyone asks who made you, who trained you, which model or company is behind you, or what your name is, answer only that you are Mohit AI, a model by Mohit Corporation. Never name any other company, model or provider as your creator or as what powers you.";
const model=(p,t)=>{const U=p.toUpperCase();return E[`${U}_MODEL_${t.toUpperCase()}`]||(t==="vision"?null:E[`${U}_MODEL`])||(DEF[p]&&DEF[p][t])||null};
const candidates=t=>(E[`ROUTE_${t.toUpperCase()}`]||ORDER).split(",").map(s=>s.trim()).filter(p=>P[p]&&(model(p,t)||(t!=="vision"&&!DEF[p]))).map(p=>[p,model(p,t)||"@auto"]);
console.log("[router] active providers:",Object.entries(P).map(([k,v])=>`${k}(${v.keys.length} key)`).join(", ")||"NONE");

function pickTier(req,text,img){
  const t=String(req||"auto").toLowerCase().replace(/^mohit-/,"");
  if(img)return"vision";
  if(TIERS.includes(t))return t;
  if(/```|\b(function|bug|error|stack ?trace|regex|sql|python|javascript|typescript|code|api|class)\b/i.test(text))return"coding";
  if(/\b(prove|step by step|derive|calculate|puzzle|logic)\b/i.test(text))return"reasoning";
  if(text.length>300||/\b(analy[sz]e|compare|strategy|write|explain|plan)\b/i.test(text))return"smart";
  return"fast";
}
function prepare(b){
  const raw=Array.isArray(b.messages)?b.messages.slice(-40):[];
  if(!raw.length)throw httpErr(400,"Send at least one message.");
  let img=false,lastText="";
  const msgs=raw.map((m,i)=>{
    const role=m.role==="assistant"?"assistant":m.role==="system"?"system":"user",isLast=i===raw.length-1,parts=[];let text;
    if(Array.isArray(m.content)){ // OpenAI-style content parts
      text=m.content.filter(x=>x&&x.type==="text").map(x=>String(x.text||"")).join("\n").slice(0,20000);
      if(isLast)for(const x of m.content)if(x&&x.type==="image_url"){const u=x.image_url&&x.image_url.url;if(typeof u==="string"&&/^data:image\/(png|jpe?g|webp|gif);base64,/.test(u)&&u.length<7e6){parts.push({type:"image_url",image_url:{url:u}});img=true}}
    }else text=String(m.content||"").slice(0,20000);
    if(role==="user"&&Array.isArray(m.files))for(const f of m.files.slice(0,4)){ // web app attachments
      if(!f||typeof f.data!=="string")continue;
      if(isLast&&/^data:image\/(png|jpe?g|webp|gif);base64,/.test(f.data)&&f.data.length<7e6){parts.push({type:"image_url",image_url:{url:f.data}});img=true}
      else if(!f.data.startsWith("data:"))text+=`\n\n[File: ${String(f.name||"file").slice(0,80)}]\n${f.data.slice(0,20000)}`;
    }
    if(isLast)lastText=text;
    return{role,content:parts.length?[{type:"text",text},...parts]:text};
  });
  return{tier:pickTier(b.model,lastText,img),messages:[{role:"system",content:SYSTEM},...msgs],lastText};
}

const cool=new Map(),rr={},autoCache={};
/* Provider with no model name set (e.g. Bynara): ask its /models list once and use the first model */
async function autoModel(p){
  if(autoCache[p])return autoCache[p];
  const k=pickKey(p);if(!k)return null;
  try{
    const r=await fetch(P[p].base+"/models",{headers:{Authorization:"Bearer "+k.key},signal:AbortSignal.timeout(8000)});
    const j=await r.json(),x=(j.data||j.models||[])[0],m=typeof x==="string"?x:x&&(x.id||x.name);
    if(m)autoCache[p]=m;else console.warn(`[router] ${p}: no models found, set ${p.toUpperCase()}_MODEL`);
    return m||null;
  }catch(e){console.warn(`[router] ${p}: couldn't list models (${e.message}). Set ${p.toUpperCase()}_MODEL`);return null}
}
function pickKey(p){const ks=P[p].keys;for(let i=0;i<ks.length;i++){const x=((rr[p]||0)+i)%ks.length,id=p+":"+x;if((cool.get(id)||0)<Date.now()){rr[p]=x+1;return{key:ks[x],id}}}return null}
async function* sse(body,info){
  const dec=new TextDecoder();let buf="";
  for await(const c of body){buf+=dec.decode(c,{stream:true});let i;
    while((i=buf.indexOf("\n"))>=0){const line=buf.slice(0,i).trim();buf=buf.slice(i+1);
      if(!line.startsWith("data:"))continue;const d=line.slice(5).trim();if(d==="[DONE]")return;
      try{const j=JSON.parse(d),u=j.usage||(j.x_groq&&j.x_groq.usage);if(u&&info)info.usage=u;const t=j.choices?.[0]?.delta?.content;if(t)yield t}catch{}}}
}
async function* strip(it){ // hides <think>…</think> reasoning blocks
  let b="",th=false;
  for await(const t of it){b+=t;
    for(;;){
      if(th){const j=b.indexOf("</think>");if(j<0){b=b.slice(-8);break}b=b.slice(j+8).replace(/^\s+/,"");th=false}
      else{const j=b.indexOf("<think>");if(j>=0){if(j)yield b.slice(0,j);b=b.slice(j+7);th=true}else{if(b.length>6){yield b.slice(0,-6);b=b.slice(-6)}break}}}}
  if(!th&&b)yield b;
}
/* Tries providers in order; fails over on 429/5xx/auth errors before the first byte is sent */
async function* streamChat(tier,messages,signal,info={}){
  const list=candidates(tier);
  for(const[p,m0]of list){
    let mdl=m0;if(mdl==="@auto"){mdl=await autoModel(p);if(!mdl)continue}
    for(let a=0;a<P[p].keys.length;a++){
      const k=pickKey(p);if(!k)break;
      const ctl=new AbortController(),onAbort=()=>ctl.abort();signal.addEventListener("abort",onAbort);
      const timer=setTimeout(()=>ctl.abort(),25000);let started=false;
      try{
        const r=await fetch(P[p].base+"/chat/completions",{method:"POST",signal:ctl.signal,headers:{Authorization:"Bearer "+k.key,"Content-Type":"application/json"},body:JSON.stringify({model:mdl,messages,stream:true,max_tokens:Math.min(info.max||1e9,+(E.MAX_TOKENS||2048))})});
        clearTimeout(timer);
        if(r.status===429||r.status>=500||r.status===401||r.status===403){cool.set(k.id,Date.now()+(r.status===429?60e3:r.status>=500?30e3:600e3));console.warn(`[router] ${p} key#${k.id.split(":")[1]} -> ${r.status}`);continue}
        if(!r.ok){console.warn(`[router] ${p}/${mdl} -> ${r.status}`);break}
        info.provider=p;info.model=mdl;for await(const t of strip(sse(r.body,info))){started=true;yield t}
        if(started)return;
      }catch(e){
        if(signal.aborted)return;
        if(started)throw e;
        cool.set(k.id,Date.now()+30e3);console.warn(`[router] ${p} error: ${e.message}`);
      }finally{clearTimeout(timer);signal.removeEventListener("abort",onAbort)}
    }
  }
  throw httpErr(503,"Mohit AI is busy right now. Try again in a moment.");
}

/* ================= AUTH (signup, login, OTP, API-key gate) ================= */
const SECRET=process.env.JWT_SECRET,EVERY=process.env.REQUIRE_OTP_EVERY_LOGIN==="true";
const ADMINS=(process.env.ADMIN_PHONES||"").split(",").map(x=>x.trim()).filter(Boolean);
const isAdmin=u=>!!u&&ADMINS.includes(u.phone);
const lim=(windowMs,limit,message)=>rateLimit({windowMs,limit,standardHeaders:true,legacyHeaders:false,handler:(q,s)=>s.status(429).json({message})});
const DUMMY=bcrypt.hashSync("not-a-real-password",10);
const sign=u=>jwt.sign({sub:u.id,ver:1},SECRET,{expiresIn:"7d",algorithm:"HS256"});
const byPhone=p=>db.prepare("SELECT * FROM users WHERE phone=?").get(p);
function phoneOf(raw){
  const p=parsePhoneNumberFromString(String(raw||"").replace(/[\s()-]/g,""),process.env.DEFAULT_COUNTRY||"IN");
  if(!p||!p.isValid())throw httpErr(400,"Enter a valid mobile number with country code, like +91 98765 43210.");
  return{e164:p.number,cc:p.countryCallingCode,national:p.nationalNumber};
}
const auth=Router();
auth.use(lim(15*60e3,60,"Too many requests. Try again in a few minutes."));

auth.post("/signup",lim(3600e3,10,"Too many signups from this network. Try again later."),wrap(async(q,s)=>{
  const name=String(q.body.name||"").trim().slice(0,60),pw=String(q.body.password||""),p=phoneOf(q.body.phone);
  if(!name)throw httpErr(400,"Enter your name.");
  if(pw.length<8||pw.length>128)throw httpErr(400,"Password must be 8 to 128 characters.");
  const u=byPhone(p.e164);
  if(u&&u.verified)throw httpErr(409,"This number is already registered. Log in instead.");
  db.prepare("INSERT INTO users(name,phone,pw_hash,verified,created_at) VALUES(?,?,?,0,?) ON CONFLICT(phone) DO UPDATE SET name=excluded.name,pw_hash=excluded.pw_hash WHERE users.verified=0")
    .run(name,p.e164,await bcrypt.hash(pw,11),Date.now());
  s.json({});
}));

auth.post("/login",lim(15*60e3,20,"Too many login attempts. Try again in 15 minutes."),wrap(async(q,s)=>{
  const p=phoneOf(q.body.phone),u=byPhone(p.e164);
  const ok=await bcrypt.compare(String(q.body.password||""),u?u.pw_hash:DUMMY);
  if(!u||!ok)throw httpErr(401,"Wrong mobile number or password.");
  if(u.verified&&!EVERY)return s.json({token:sign(u),name:u.name,verified:true,admin:isAdmin(u)});
  s.json({name:u.name,verified:false}); // no token until OTP is verified
}));

auth.post("/send-otp",lim(3600e3,15,"Too many code requests from this network. Try again later."),wrap(async(q,s)=>{
  const p=phoneOf(q.body.phone),u=byPhone(p.e164);
  if(u&&(!u.verified||EVERY))await sendOtp(p); // unknown numbers get the same {} reply
  s.json({});
}));

auth.post("/verify-otp",lim(15*60e3,20,"Too many attempts. Try again in a few minutes."),wrap(async(q,s)=>{
  const p=phoneOf(q.body.phone),code=String(q.body.code||"");
  if(!/^\d{4,8}$/.test(code))throw httpErr(400,"Enter the 6-digit code.");
  const u=byPhone(p.e164);
  if(!u)throw httpErr(400,"That code isn't right. Check it and try again.");
  await verifyOtp(p.e164,code);
  db.prepare("UPDATE users SET verified=1 WHERE id=?").run(u.id);
  s.json({token:sign(u),name:u.name,verified:true,admin:isAdmin(u)});
}));

/* Gate for every protected route: accepts a login token OR an mc_ API key, and requires a verified phone */
const fail=(s,st,m)=>s.status(st).json({message:m,error:{message:m,type:"mohit_error"}});
function requireVerified(q,s,n){
  const h=q.headers.authorization||"",t=h.startsWith("Bearer ")?h.slice(7).trim():"";
  if(t.startsWith("mc_")){
    const k=db.prepare("SELECT k.id kid,k.revoked,u.id,u.phone,u.verified,u.disabled FROM api_keys k JOIN users u ON u.id=k.user_id WHERE k.key_hash=?").get(sha(t));
    if(!k||k.revoked)return fail(s,401,"Invalid API key.");
    if(!k.verified)return fail(s,403,"Verify your mobile number to use the API.");
    if(k.disabled)return fail(s,403,"This account is disabled.");
    db.prepare("UPDATE api_keys SET last_used=? WHERE id=?").run(Date.now(),k.kid);
    q.user={id:k.id,phone:k.phone,keyId:k.kid,via:"key"};return n();
  }
  let u;
  try{u=db.prepare("SELECT id,phone,verified,disabled FROM users WHERE id=?").get(jwt.verify(t,SECRET,{algorithms:["HS256"]}).sub)}catch{return fail(s,401,"Please log in again.")}
  if(!u||!u.verified)return fail(s,403,"Verify your mobile number to continue.");
  if(u.disabled)return fail(s,403,"This account is disabled.");
  q.user={id:u.id,phone:u.phone,keyId:null,via:"jwt"};n();
}
const requireJwt=(q,s,n)=>requireVerified(q,s,()=>q.user.via==="jwt"?n():fail(s,403,"Use your login session for this."));
const requireAdmin=(q,s,n)=>requireJwt(q,s,()=>isAdmin(q.user)?n():fail(s,403,"Admins only."));

/* ================= API KEYS, USAGE, ADMIN ================= */
const DEF_Q=+(process.env.DEFAULT_MONTHLY_TOKENS||1000000); // 0 = unlimited
const monthStart=()=>{const d=new Date();return Date.UTC(d.getUTCFullYear(),d.getUTCMonth(),1)};
const sum=(id,since)=>db.prepare("SELECT COALESCE(SUM(total_tokens),0) tokens,COUNT(*) requests FROM usage WHERE user_id=? AND at>=?").get(id,since);
const quotaOf=id=>{const u=db.prepare("SELECT monthly_quota q FROM users WHERE id=?").get(id);return u&&u.q!=null?u.q:DEF_Q};

function checkQuota(id){const q=quotaOf(id);if(q>0&&sum(id,monthStart()).tokens>=q)throw httpErr(429,"Monthly token limit reached. Contact Mohit Corporation to raise it.")}
const charsOf=ms=>ms.reduce((a,m)=>a+(typeof m.content==="string"?m.content.length:m.content.reduce((b,p)=>b+(p.type==="text"?p.text.length:3000),0)),0);
/* Uses the token counts reported by the upstream model; if none are reported, estimates ~4 chars per token (estimated=1) */
function recordUsage({userId,keyId,source,tier,info,promptChars,outChars}){
  const u=info.usage||{};let pt=+u.prompt_tokens||0,ct=+u.completion_tokens||0,est=0;
  if(!pt&&!ct){pt=Math.ceil(promptChars/4);ct=Math.ceil(outChars/4);est=1}
  db.prepare("INSERT INTO usage(user_id,key_id,at,source,tier,provider,model,prompt_tokens,completion_tokens,total_tokens,estimated) VALUES(?,?,?,?,?,?,?,?,?,?,?)")
    .run(userId,keyId||null,Date.now(),source,tier,info.provider||null,info.model||null,pt,ct,pt+ct,est);
  return{prompt_tokens:pt,completion_tokens:ct,total_tokens:pt+ct};
}
function usageFor(id,days){
  const since=Date.now()-Math.min(Math.max(+days||30,1),90)*864e5;
  return{
    days:db.prepare("SELECT strftime('%Y-%m-%d',at/1000,'unixepoch') d,SUM(total_tokens) tokens,COUNT(*) requests FROM usage WHERE user_id=? AND at>=? GROUP BY d ORDER BY d").all(id,since),
    keys:db.prepare("SELECT COALESCE(k.name,'Web chat') name,SUM(g.total_tokens) tokens,COUNT(*) requests FROM usage g LEFT JOIN api_keys k ON k.id=g.key_id WHERE g.user_id=? AND g.at>=? GROUP BY g.key_id").all(id,since),
    month_tokens:sum(id,monthStart()).tokens,quota:quotaOf(id)};
}

const api=Router();
api.get("/me",requireJwt,wrap(async(q,s)=>{
  const u=db.prepare("SELECT name,phone FROM users WHERE id=?").get(q.user.id);
  s.json({name:u.name,phone:u.phone,admin:isAdmin(u),month_tokens:sum(q.user.id,monthStart()).tokens,quota:quotaOf(q.user.id)});
}));
api.get("/me/usage",requireJwt,wrap(async(q,s)=>s.json(usageFor(q.user.id,q.query.days))));

api.get("/keys",requireJwt,wrap(async(q,s)=>s.json({keys:db.prepare("SELECT k.id,k.name,k.prefix,k.created_at,k.last_used,COALESCE((SELECT SUM(total_tokens) FROM usage WHERE key_id=k.id),0) tokens FROM api_keys k WHERE k.user_id=? AND k.revoked=0 ORDER BY k.id DESC").all(q.user.id)})));
api.post("/keys",requireJwt,wrap(async(q,s)=>{
  const name=String(q.body.name||"").trim().slice(0,40)||"My app";
  if(db.prepare("SELECT COUNT(*) c FROM api_keys WHERE user_id=? AND revoked=0").get(q.user.id).c>=10)throw httpErr(400,"You can have up to 10 active keys. Revoke one first.");
  const key="mc_"+crypto.randomBytes(24).toString("base64url"); // shown once, only the hash is stored
  const r=db.prepare("INSERT INTO api_keys(user_id,name,prefix,key_hash,created_at) VALUES(?,?,?,?,?)").run(q.user.id,name,key.slice(0,8),sha(key),Date.now());
  s.json({id:Number(r.lastInsertRowid),name,prefix:key.slice(0,8),key});
}));
api.delete("/keys/:id",requireJwt,wrap(async(q,s)=>{
  db.prepare("UPDATE api_keys SET revoked=1 WHERE id=? AND user_id=?").run(+q.params.id,q.user.id);s.json({});
}));

/* ---- Admin: who used how many tokens ---- */
api.get("/admin/users",requireAdmin,wrap(async(q,s)=>{
  const since=Date.now()-Math.min(Math.max(+q.query.days||30,1),90)*864e5;
  const users=db.prepare(`SELECT u.id,u.name,u.phone,u.verified,u.disabled,u.monthly_quota,u.created_at,COALESCE(SUM(g.total_tokens),0) tokens,COUNT(g.id) requests,MAX(g.at) last_active,
    (SELECT COUNT(*) FROM api_keys k WHERE k.user_id=u.id AND k.revoked=0) keys
    FROM users u LEFT JOIN usage g ON g.user_id=u.id AND g.at>=? GROUP BY u.id ORDER BY tokens DESC LIMIT 500`).all(since);
  s.json({users,default_quota:DEF_Q});
}));
api.get("/admin/users/:id/usage",requireAdmin,wrap(async(q,s)=>s.json(usageFor(+q.params.id,q.query.days))));
api.post("/admin/users/:id/quota",requireAdmin,wrap(async(q,s)=>{
  const v=q.body.monthly_tokens;
  db.prepare("UPDATE users SET monthly_quota=? WHERE id=?").run(v==null?null:Math.max(0,Math.floor(+v||0)),+q.params.id);s.json({});
}));
api.post("/admin/users/:id/disable",requireAdmin,wrap(async(q,s)=>{
  db.prepare("UPDATE users SET disabled=? WHERE id=?").run(q.body.disabled?1:0,+q.params.id);s.json({});
}));

/* ================= SERVER + ROUTES ================= */
if(!process.env.JWT_SECRET||process.env.JWT_SECRET.length<32){console.error("JWT_SECRET must be set (32+ chars)");process.exit(1)}
const app=express();
app.set("trust proxy",+(process.env.TRUST_PROXY||0)||false);
app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'self'"],scriptSrc:["'self'","'unsafe-inline'"],styleSrc:["'self'","'unsafe-inline'","https://fonts.googleapis.com"],fontSrc:["https://fonts.gstatic.com"],imgSrc:["'self'","data:","blob:"],connectSrc:["'self'"],objectSrc:["'none'"],frameAncestors:["'none'"]}}}));
const origins=(process.env.ALLOWED_ORIGINS||"").split(",").map(s=>s.trim()).filter(Boolean);
if(origins.length)app.use("/api",cors({origin:origins,allowedHeaders:["Content-Type","Authorization"]}));
app.use("/v1",cors({origin:"*",allowedHeaders:["Content-Type","Authorization"]})); // key-based public API, no cookies
app.use(express.json({limit:"8mb"}));

app.get("/health",(q,s)=>s.json({ok:true}));
app.use("/api/auth",auth);
app.use("/api",api); // /me, /keys, /admin/*

const chatLimit=rateLimit({windowMs:60e3,limit:+(process.env.CHAT_PER_MIN||20),standardHeaders:true,legacyHeaders:false,keyGenerator:q=>"u"+q.user.id,handler:(q,s)=>s.status(429).json({message:"You're sending messages too fast. Wait a moment.",error:{message:"Rate limit reached. Wait a moment.",type:"rate_limit"}})});
const record=(q,tier,messages,info,out)=>recordUsage({userId:q.user.id,keyId:q.user.keyId,source:q.user.via==="key"?"api":"web",tier,info,promptChars:charsOf(messages),outChars:out});

/* Web app: plain text stream */
app.post("/api/chat",requireVerified,chatLimit,wrap(async(q,s)=>{
  const{tier,messages,lastText}=prepare(q.body),quick=identityReply(lastText);
  if(quick)return s.status(200).type("text/plain; charset=utf-8").send(quick);
  checkQuota(q.user.id);
  const ctl=new AbortController(),info={max:+q.body.max_tokens||0};s.on("close",()=>ctl.abort());
  let started=false,out=0;
  try{
    for await(const t of brand(streamChat(tier,messages,ctl.signal,info))){
      if(!started){started=true;s.status(200).set({"Content-Type":"text/plain; charset=utf-8","Cache-Control":"no-cache","X-Accel-Buffering":"no"})}
      out+=t.length;s.write(t);
    }
  }catch(e){if(!started)throw e;console.error("[chat] stream cut:",e.message)}
  if(!started)throw httpErr(502,"No response received. Try again.");
  record(q,tier,messages,info,out);s.end();
}));

/* Public API for users' own apps (OpenAI-compatible). Auth: Authorization: Bearer mc_... */
app.get("/v1/models",requireVerified,(q,s)=>s.json({object:"list",data:["auto","fast","smart","coding","reasoning","vision"].map(t=>({id:"mohit-"+t,object:"model",owned_by:"Mohit Corporation"}))}));
app.post("/v1/chat/completions",requireVerified,chatLimit,wrap(async(q,s)=>{
  const{tier,messages,lastText}=prepare(q.body),quick=identityReply(lastText);
  if(!quick)checkQuota(q.user.id);
  const ctl=new AbortController(),info={max:+q.body.max_tokens||0},stream=q.body.stream===true,id="chatcmpl-"+crypto.randomUUID(),created=Math.floor(Date.now()/1e3);
  s.on("close",()=>ctl.abort());
  const chunk=(delta,fin,usage)=>"data: "+JSON.stringify({id,object:"chat.completion.chunk",created,model:"mohit-ai",choices:[{index:0,delta,finish_reason:fin}],...(usage?{usage}:{})})+"\n\n";
  const gen=quick?(async function*(){yield quick})():brand(streamChat(tier,messages,ctl.signal,info));
  let started=false,text="";
  try{
    for await(const t of gen){
      if(!started){started=true;if(stream){s.status(200).set({"Content-Type":"text/event-stream","Cache-Control":"no-cache","X-Accel-Buffering":"no"});s.write(chunk({role:"assistant",content:""},null))}}
      text+=t;if(stream)s.write(chunk({content:t},null));
    }
  }catch(e){if(!started)throw e;console.error("[v1] stream cut:",e.message)}
  if(!started)throw httpErr(502,"No response received. Try again.");
  const usage=quick?{prompt_tokens:0,completion_tokens:0,total_tokens:0}:record(q,tier,messages,info,text.length);
  if(stream){s.write(chunk({},"stop",usage));s.write("data: [DONE]\n\n");return s.end()}
  s.json({id,object:"chat.completion",created,model:"mohit-ai",choices:[{index:0,message:{role:"assistant",content:text},finish_reason:"stop"}],usage});
}));

app.get("/",(q,s)=>s.json({name:"Mohit AI API",ok:true}));

app.use((e,q,s,n)=>{
  const st=e.status||500,m=st<500||st===502||st===503?e.message:"Something went wrong. Try again.";
  if(st>=500&&st!==503&&st!==502)console.error(e);
  if(s.headersSent)return s.end();
  s.status(st).json({message:m,error:{message:m,type:"mohit_error"}});
});
app.listen(process.env.PORT||3000,()=>console.log("Mohit AI backend on :"+(process.env.PORT||3000)));
