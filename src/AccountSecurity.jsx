import React,{useCallback,useEffect,useState} from 'react';
import {multiFactor,TotpMultiFactorGenerator} from '@firebase/auth';
import {CheckCircle2,Copy,KeyRound,LockKeyhole,ShieldCheck,Smartphone} from 'lucide-react';

export function AccountSecurity({firebaseAuth,firebaseProvider,notify}) {
 const [factors,setFactors]=useState([]);
 const [secret,setSecret]=useState(null);
 const [otpAuthUrl,setOtpAuthUrl]=useState('');
 const [secretKey,setSecretKey]=useState('');
 const [code,setCode]=useState('');
 const [busy,setBusy]=useState(false);
 const user=firebaseAuth?.currentUser;
 const refresh=useCallback(async()=>{
  if(!user){setFactors([]);return}
  await user.reload();
  setFactors(multiFactor(user).enrolledFactors.filter(f=>f.factorId==='totp'));
 },[user]);
 useEffect(()=>{refresh().catch(e=>notify(e.message))},[refresh,notify]);
 const begin=async()=>{
  setBusy(true);
  try{
   if(!user)throw new Error('Your Firebase browser session is unavailable. Sign in again before changing MFA.');
   const session=await multiFactor(user).getSession();
   const next=await TotpMultiFactorGenerator.generateSecret(session);
   setSecret(next);
   setSecretKey(next.secretKey);
   setOtpAuthUrl(next.generateQrCodeUrl(user.email||user.uid,'CloudShield'));
   setCode('');
  }catch(e){notify(e.message)}finally{setBusy(false)}
 };
 const confirm=async()=>{
  setBusy(true);
  try{
   if(!secret||!/^\d{6}$/.test(code))throw new Error('Enter the current six-digit code from your authenticator app.');
   const assertion=TotpMultiFactorGenerator.assertionForEnrollment(secret,code);
   await multiFactor(user).enroll(assertion,'CloudShield authenticator');
   setSecret(null);setSecretKey('');setOtpAuthUrl('');setCode('');
   await refresh();notify('TOTP authenticator enrolled successfully.');
  }catch(e){notify(e.message)}finally{setBusy(false)}
 };
 const remove=async factor=>{
  if(!window.confirm('Remove this authenticator from your CloudShield account? Make sure another factor or account recovery path is available.'))return;
  setBusy(true);
  try{await multiFactor(user).unenroll(factor.uid);await refresh();notify('Authenticator removed.')}
  catch(e){notify(e.message)}finally{setBusy(false)}
 };
 if(!firebaseProvider)return <section className="panel"><h2>Account security</h2><p>Multi-factor authentication and organization SSO are available through the Firebase Identity Platform sign-in provider. This workspace is not currently using Firebase authentication.</p></section>;
 return <div className="cloud-ops-stack">
  <section className="panel cloud-panel">
   <div className="panel-head"><div><span className="overline">IDENTITY PROTECTION</span><h2>Authenticator-based MFA</h2></div><span className="source-status status-ok"><i/>{factors.length?'TOTP enrolled':'Not enrolled'}</span></div>
   <div className="insight-banner"><ShieldCheck size={19}/><div><b>Use a TOTP authenticator</b><p>CloudShield supports Firebase TOTP second-factor challenges. Enroll at least two authenticators or devices before an administrator enforces MFA for the project. Keep account recovery access available.</p></div></div>
   <div className="factor-list">{factors.map((factor,index)=><div className="factor-row" key={factor.uid}><Smartphone size={18}/><div><b>{factor.displayName||'TOTP authenticator '+(index+1)}</b><small>Enrolled {factor.enrollmentTime?new Date(factor.enrollmentTime).toLocaleString():'on this account'}</small></div><button className="button button-soft" disabled={busy||factors.length===1} onClick={()=>remove(factor)}>Remove</button></div>)}{!factors.length&&<div className="cloud-empty"><LockKeyhole size={20}/>No TOTP factor enrolled on this Firebase account.</div>}</div>
   {!secret&&<button className="button button-primary" disabled={busy||!user} onClick={begin}>{busy?'Preparingâ€¦':factors.length?'Add another authenticator':'Set up authenticator'}</button>}
   {secret&&<div className="totp-enrollment">
    <h3>1. Add this account to your authenticator</h3>
    <p>In your authenticator app, choose manual setup / enter setup key. Use the account label shown below and select time-based one-time password (TOTP).</p>
    <label className="cloud-field">Account<input readOnly value={user?.email||user?.uid||''}/></label>
    <label className="cloud-field">Secret key<input readOnly value={secretKey}/></label>
    <div className="cloud-actions"><button className="button button-soft" onClick={()=>navigator.clipboard.writeText(secretKey)}><Copy size={14}/> Copy secret key</button><button className="button button-soft" onClick={()=>navigator.clipboard.writeText(otpAuthUrl)}><Copy size={14}/> Copy otpauth URI</button></div>
    <p className="provider-error">Treat this setup key like a password. It is displayed only during enrollment and is not sent to CloudShield's application server.</p>
    <h3>2. Verify your authenticator</h3>
    <label className="cloud-field">Six-digit code<input inputMode="numeric" autoComplete="one-time-code" value={code} onChange={e=>setCode(e.target.value.replace(/\D/g,'').slice(0,6))} maxLength={6} placeholder="123456"/></label>
    <div className="cloud-actions"><button className="button button-primary" disabled={busy||code.length!==6} onClick={confirm}>{busy?'Verifyingâ€¦':'Confirm and enroll'}</button><button className="button button-soft" disabled={busy} onClick={()=>{setSecret(null);setSecretKey('');setOtpAuthUrl('');setCode('')}}>Cancel</button></div>
   </div>}
  </section>
  <section className="panel cloud-panel"><div className="panel-head"><div><span className="overline">SINGLE SIGN-ON</span><h2>Organization identity provider</h2></div></div><p className="cloud-description">Organization SSO is configured by the CloudShield deployment administrator in Firebase Identity Platform. The sign-in screen displays the configured OIDC or SAML provider. Your organization administrator must validate provider claims, domains and redirect URLs.</p></section>
 </div>;
}
