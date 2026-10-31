export type Wallet = {address:string; verified_at:string};
export type Role = 'guardian'|'recovery'|'notification';
export type Assignment = {id:string;owner_wallet:string;candidate_wallet:string;role:Role;status:'awaiting_consent'|'pending'|'active'|'cancelled'|'removed';proposed_at:string;executable_at:string;accepted_at:string|null;delay_seconds:number};
export type ContactStatus = {id:string;kind:'email'|'telegram';status:string;removal_at:string|null};
export type ChainStatus = {status:'unavailable'|'ready';chain_id:string;reason:string;contracts:unknown[]};
export type Me = {authenticated:boolean;csrf_token?:string;profile_id?:string;anchor_wallet?:string;wallets:Wallet[];assignments:Assignment[];contacts:ContactStatus[];chain:ChainStatus};
export type Challenge = {id:string;message:string;expires_at:string;chain_id:string};
let csrf = '';
export function setCsrf(value:string){csrf=value;}
export async function api<T>(path:string,body?:unknown):Promise<T>{
 const response=await fetch('/api/v1'+path,{method:body===undefined?'GET':'POST',credentials:'same-origin',headers:body===undefined?{}:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:body===undefined?undefined:JSON.stringify(body)});
 const data=await response.json(); if(!response.ok)throw new Error(data.error||'Request failed'); return data as T;
}
