import React, { useEffect, useRef, useState } from 'react';
import { identity, registration, decryptBlob, toHex } from '../../client-core/src/crypto.js';
import { fetchKey, signedFetch, signedRequest, upload } from '../../client-core/src/api.js';
import { download, reader } from '../../client-core/src/chainRead.js';
import { cachedKey, cacheEnabled, cacheKey, getIdentities, saveIdentity, setCacheEnabled } from './state/identity.js';

const short = s => s ? s.slice(0, 8) + '…' + s.slice(-5) : '—';
const bytes = n => n < 1024 ? `${n} B` : `${(n / 1024).toFixed(1)} KB`;
function Badge({ children, muted = false }) { return <span className={`badge ${muted ? 'muted' : ''}`}>{children}</span>; }
function Field({ label, ...props }) { return <label className="field"><span>{label}</span><input {...props}/></label>; }
function Empty({ title, children }) { return <div className="empty"><div className="empty-icon">◇</div><h3>{title}</h3><p>{children}</p></div>; }

export default function App() {
  const [ids, setIds] = useState([]), [current, setCurrent] = useState('');
  const [config, setConfig] = useState(null), [chain, setChain] = useState(null), [health, setHealth] = useState({});
  const [groups, setGroups] = useState([]), [groupId, setGroupId] = useState(''), [group, setGroup] = useState(null);
  const [files, setFiles] = useState([]), [status, setStatus] = useState(null), [tab, setTab] = useState('Files');
  const [busy, setBusy] = useState(false), [notice, setNotice] = useState(null), [stage, setStage] = useState('');
  const [newName, setNewName] = useState(''), [groupName, setGroupName] = useState(''), [joinId, setJoinId] = useState('');
  const [showNew, setShowNew] = useState(false), [cache, setCache] = useState(true), [mode, setMode] = useState('lazy'), [result, setResult] = useState(null);
  const [audit, setAudit] = useState([]), [recordInput, setRecordInput] = useState(''), [inspect, setInspect] = useState(null), [cipher, setCipher] = useState(null), [plaintext, setPlaintext] = useState('');
  const [attackG, setAttackG] = useState(''), [attackCid, setAttackCid] = useState(''), [attackV, setAttackV] = useState('1'), [attackResult, setAttackResult] = useState('');
  const fileInput = useRef(), selectedRef = useRef('');
  const id = ids.find(i => i.userId === current);
  selectedRef.current = `${current}:${groupId}`;
  const owner = group?.ownerId === current;
  const api = (method, path, body) => signedFetch(id, method, path, body);
  const retainKey = keys => cacheKey(id, groupId, keys);

  async function refresh() {
    if (!id) return;
    const snapshot = `${current}:${groupId}`;
    const all = await api('GET', '/me/groups');
    if (selectedRef.current !== snapshot) return;
    setGroups(all);
    if (groupId) {
      const membership = all.find(g => g.groupId === groupId);
      if (membership?.status !== 'active') { setGroup(null); setFiles([]); setStatus(null); return; }
      const [info, rows] = await Promise.all([api('GET', `/groups/${groupId}`), api('GET', `/groups/${groupId}/files`)]);
      const state = info.ownerId === current ? await api('GET', `/admin/groups/${groupId}/status`) : null;
      if (selectedRef.current !== snapshot) return;
      setGroup(info); setFiles(rows); setStatus(state);
    }
  }
  async function run(fn, success) {
    setBusy(true); setNotice(null);
    try { await fn(); if (success) setNotice({ text: success }); await refresh(); }
    catch (e) { setNotice({ error: true, text: `${e.code || e.name}: ${e.message}` }); }
    finally { setBusy(false); }
  }
  useEffect(() => {
    getIdentities().then(items => { setIds(items); setCurrent(items[0]?.userId || ''); });
    cacheEnabled().then(setCache);
    fetch('/public/config').then(r => r.json()).then(c => { setConfig(c); setChain(reader(c)); }).catch(() => setNotice({ error: true, text: 'Proxy unavailable. Start the local services.' }));
    const check = () => fetch('/health').then(r => r.json()).then(setHealth).catch(() => setHealth({}));
    check(); const timer = setInterval(check, 10000); return () => clearInterval(timer);
  }, []);
  useEffect(() => {
    setGroup(null); setFiles([]); setStatus(null); setPlaintext(''); setStage('');
    refresh().catch(e => setNotice({ error: true, text: e.message }));
    const timer = setInterval(() => refresh().catch(() => {}), 3000);
    return () => clearInterval(timer);
  }, [current, groupId]);
  useEffect(() => { if (tab === 'Audit' && groupId && chain) run(async () => setAudit(await chain.audit(groupId))); }, [tab, groupId, chain]);
  async function register() {
    const person = await identity(newName.trim());
    const response = await fetch('/users/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(await registration(person)) });
    if (!response.ok) throw Error((await response.json()).code);
    await saveIdentity(person); setIds(await getIdentities()); setCurrent(person.userId); setNewName(''); setShowNew(false); setGroupId('');
  }
  async function sendFile(file) {
    if (!file) return;
    if (file.size > 50 * 1024 * 1024) throw Error('Browser uploads are limited to 50 MB.');
    await upload(id, groupId, new Uint8Array(await file.arrayBuffer()), '', setStage, retainKey, { filename: file.name, mimeType: file.type });
  }
  async function receive(recordId, show = false) {
    const { plain, filename, mimeType } = await download(id, recordId, chain, '', setStage, (keys, g) => cacheKey(id, g, keys));
    if (show) { setPlaintext(new TextDecoder().decode(plain)); return; }
    const url = URL.createObjectURL(new Blob([plain], { type: mimeType }));
    const a = document.createElement('a'); a.href = url; a.download = filename; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  async function inspectRecord() {
    const record = await chain.get(recordInput); setInspect(record); setPlaintext('');
    setAttackG(record.groupId); setAttackCid(record.cid); setAttackV(String(record.keyVersion));
    const response = await fetch(`/public/ipfs/${record.cid}`);
    setCipher(response.ok ? new Uint8Array(await response.arrayBuffer()) : null);
  }
  async function attack(action) {
    try {
      if (action === 'cipher') {
        const r = await fetch(`/public/ipfs/${attackCid}`);
        if (!r.ok) throw Error('Ciphertext unavailable on this node');
        const blob = new Uint8Array(await r.arrayBuffer()); setCipher(blob);
        setAttackResult(`Public ciphertext fetched: ${blob.length} bytes. ${toHex(blob.slice(0, 64))}`);
      } else if (action === 'key' || action === 'old') {
        const keys = await fetchKey(id, attackG, action === 'key' ? 'current' : attackV);
        await cacheKey(id, attackG, keys); setAttackResult(`Access granted to version ${keys.version}. Key bytes remain hidden.`);
      } else if (action === 'cached') {
        const keys = await cachedKey(id, attackG, Number(attackV));
        if (!keys) throw Error('No cached key for this identity, group, and version');
        const response = await fetch(`/public/ipfs/${attackCid}`);
        if (!response.ok) throw Error('Ciphertext unavailable on this node');
        const plain = await decryptBlob(keys.aesKey, new Uint8Array(await response.arrayBuffer()), attackG, Number(attackV));
        setAttackResult(`Cached key decrypted ${plain.length} bytes. Revocation cannot recall keys or ciphertext already copied.`);
      } else if (action === 'replay') {
        const req = await signedRequest(id, 'GET', '/me/groups');
        await fetch('/me/groups', req);
        const r = await fetch('/me/groups', req);
        setAttackResult(`Replay result: HTTP ${r.status} · ${(await r.json()).code}`);
      } else {
        const keys = await fetchKey(id, attackG, attackV);
        const r = await fetch(`/public/ipfs/${attackCid}`);
        if (!r.ok) throw Error('Ciphertext unavailable');
        const blob = new Uint8Array(await r.arrayBuffer()); blob[13] ^= 1;
        await decryptBlob(keys.aesKey, blob, attackG, Number(attackV));
      }
    } catch (e) { setAttackResult(`${e.code || e.name}: ${e.message}`); }
  }
  return <div className="app-shell">
    <aside className="sidebar">
      <a className="brand" href="#" onClick={() => { setGroupId(''); setTab('Files'); }}><span className="brand-mark">S</span><span>SecureFile<small>ENCRYPTED WORKSPACE</small></span></a>
      <div className="nav-label">WORKSPACE</div>
      <button className={!groupId && tab !== 'Attacker' ? 'nav active' : 'nav'} onClick={() => { setGroupId(''); setTab('Files'); }}>▦ <span>My groups</span><span className="nav-count">{groups.length}</span></button>
      <button className={tab === 'Attacker' ? 'nav active' : 'nav'} onClick={() => setTab('Attacker')}>◇ <span>Security lab</span></button>
      <div className="nav-label">YOUR GROUPS</div>
      {groups.map(g => <button key={g.groupId} className={`nav group-nav ${groupId === g.groupId ? 'active' : ''}`} onClick={() => { setGroupId(g.groupId); setTab('Files'); }}><span className="group-dot"/><span>{g.name}</span><small>{g.status === 'active' ? `v${g.currentVersion}` : g.status}</small></button>)}
      <div className="sidebar-note"><span>◈</span><strong>Your files. Your circle.</strong><p>Encrypted on your device before they leave it.</p><small>LOCAL DEMO · IPFS + BLOCKCHAIN</small></div>
    </aside>
    <div className="workspace">
      <header className="topbar"><div className="breadcrumb"><button onClick={() => { setGroupId(''); setTab('Files'); }}>Workspace</button> <span>/</span> {tab === 'Attacker' ? 'Security lab' : groupId ? group?.name || 'Group' : 'My groups'}</div><div className="identity-bar"><label htmlFor="identity">Acting as</label><select id="identity" value={current} disabled={busy} onChange={e => { setCurrent(e.target.value); setInspect(null); setPlaintext(''); setAttackResult(''); }}><option value="" disabled>Select identity</option>{ids.map(i => <option key={i.userId} value={i.userId}>{i.name} · {i.userId.slice(0, 6)}</option>)}</select><button className="button secondary small" onClick={() => setShowNew(!showNew)}>+ New identity</button></div></header>
      <main>
        {showNew && <form className="panel inline-form" onSubmit={e => { e.preventDefault(); run(register, 'Identity created and registered.'); }}><Field label="Identity name" placeholder="e.g. Alice" value={newName} maxLength={100} onChange={e => setNewName(e.target.value)} required/><button className="button" disabled={busy}>Create secure identity</button><small>Private keys stay in this browser.</small></form>}
        {notice && <div role="alert" className={`notice ${notice.error ? 'error' : ''}`}>{notice.text}<button aria-label="Dismiss" onClick={() => setNotice(null)}>×</button></div>}
        {!id && <section className="welcome panel"><span className="eyebrow">A PRIVATE SPACE FOR SHARED WORK</span><h1>Share the work.<br/>Keep the trust.</h1><p>Create a local identity to start a group, encrypt files, and decide who has access.</p><button className="button" onClick={() => setShowNew(true)}>Create your first identity ↗</button><div className="welcome-steps"><span>01 · Encrypt on device</span><span>02 · Store on IPFS</span><span>03 · Verify on chain</span></div></section>}
        {id && tab !== 'Attacker' && !groupId && <>
          <div className="page-heading"><div><span className="eyebrow">YOUR ENCRYPTED WORKSPACE</span><h1>My groups<span className="title-dot">.</span></h1><p>A shared space for files. Access stays with the people you choose.</p></div><Badge>{groups.filter(g => g.status === 'active').length} active groups</Badge></div>
          <div className="stats-row"><div><small>YOUR IDENTITY</small><strong>{id.name}</strong><code>{short(id.userId)}</code></div><div><small>ENCRYPTION</small><strong>AES-256-GCM</strong><span>On your device</span></div><div><small>VERIFICATION</small><strong>On-chain records</strong><span>Independent integrity checks</span></div></div>
          <div className="section-heading"><h2>Your circles</h2><span>{groups.length} groups</span></div>
          <div className="group-grid">{groups.map(g => <button className="group-card" key={g.groupId} onClick={() => setGroupId(g.groupId)}><div className="card-top"><span className="folder-icon">▱</span><Badge muted={g.status !== 'active'}>{g.status}</Badge></div><h3>{g.name}</h3><p>{short(g.groupId)}</p><div className="card-bottom"><span>{g.role} · Key v{g.currentVersion}</span><span>↗</span></div></button>)}</div>
          {!groups.length && <Empty title="Your first circle starts here">Create a group below, or join one using an invitation ID.</Empty>}
          <div className="two-cols forms"><form className="panel" onSubmit={e => { e.preventDefault(); run(async () => { const g = await api('POST', '/groups', { name: groupName }); setGroupId(g.groupId); setGroupName(''); }, 'Group created.'); }}><h3>Create a group</h3><p>Start a space and invite your collaborators.</p><Field label="Group name" placeholder="e.g. Research team" value={groupName} onChange={e => setGroupName(e.target.value)} maxLength={100} required/><button className="button" disabled={busy}>Create group ↗</button></form><form className="panel" onSubmit={e => { e.preventDefault(); run(async () => { await api('POST', `/groups/${joinId.trim()}/join-requests`); setJoinId(''); }, 'Join request sent to the owner.'); }}><h3>Join a group</h3><p>Ask the owner to approve your access.</p><Field label="Group ID" placeholder="Paste a 32-character group ID" value={joinId} onChange={e => setJoinId(e.target.value)} pattern="[a-f0-9]{32}" required/><button className="button secondary" disabled={busy}>Request access →</button></form></div>
        </>}
        {id && groupId && tab !== 'Attacker' && <>
          <div className="page-heading"><div><span className="eyebrow">SHARED, WITH INTENTION</span><h1>{group?.name || groups.find(g => g.groupId === groupId)?.name || 'Group'}</h1><button className="copy-id" onClick={() => run(() => navigator.clipboard.writeText(groupId), 'Group ID copied.')}>{groupId} <span>Copy ID ↗</span></button></div><Badge>{groups.find(g => g.groupId === groupId)?.status || 'No membership'}</Badge></div>
          {!group ? <Empty title="Waiting for access">Only active members can open this group. Your membership status appears above.</Empty> : <>
            <nav className="tabs" aria-label="Group sections">{['Files', 'Members', ...(owner ? ['Keys & Versions'] : []), 'Audit', 'Inspector'].map(t => <button className={tab === t ? 'selected' : ''} key={t} onClick={() => { setTab(t); setResult(null); }}>{t}{t === 'Files' && <span>{files.filter(f => f.status === 'active').length}</span>}</button>)}</nav>
            {tab === 'Files' && <>
              <div className="upload-zone" onDragOver={e => e.preventDefault()} onDrop={e => { e.preventDefault(); if (!busy) run(() => sendFile(e.dataTransfer.files[0])); }}><div className="upload-icon">↑</div><h3>Drop a file. We’ll encrypt it here.</h3><p>Only ciphertext leaves your browser · Up to 50 MB</p><input type="file" ref={fileInput} hidden onChange={e => { const file = e.target.files[0]; e.target.value = ''; run(() => sendFile(file)); }}/><button className="button secondary" disabled={busy} onClick={() => fileInput.current.click()}>Choose a file</button></div>
              {stage && <div className="stage" role="status">{busy ? '◌' : '✓'} {stage}</div>}
              <div className="section-heading"><h2>Group files</h2><small>Filenames are encrypted. Downloads preserve the original name and extension.</small></div>
              <div className="table-wrap"><table><thead><tr><th>File record</th><th>Uploaded by</th><th>Size</th><th>Key</th><th>Status</th><th>Actions</th></tr></thead><tbody>{files.map(f => <tr key={f.recordId}><td><strong>▤ Record #{f.recordId}</strong><code title={f.cid}>{short(f.cid)}</code></td><td>{f.uploaderName}</td><td>{bytes(f.size)}</td><td><Badge>v{f.keyVersion}</Badge></td><td>{f.status}</td><td>{f.status === 'active' && <div className="actions"><button disabled={busy} onClick={() => run(() => receive(f.recordId))}>Download</button>{(owner || f.uploaderId === current) && <button disabled={busy} className="danger" onClick={() => run(() => api('DELETE', `/groups/${groupId}/files/${f.recordId}`), 'File removed; its chain record remains.')}>Remove</button>}<button onClick={() => { setRecordInput(String(f.recordId)); setTab('Inspector'); }}>Inspect</button></div>}</td></tr>)}</tbody></table></div>
              {!files.length && <Empty title="Ready for your first file">Every upload gets an immutable record and a verifiable history.</Empty>}
            </>}
            {tab === 'Members' && <><div className="section-heading"><h2>People with access</h2>{owner && config?.demoMode && <label>Revocation mode <select value={mode} onChange={e => setMode(e.target.value)}><option value="lazy">Lazy · rotate key only</option><option value="eager">Eager · re-encrypt all files</option></select></label>}</div><div className="table-wrap"><table><thead><tr><th>Identity</th><th>Role</th><th>Status</th><th>Actions</th></tr></thead><tbody>{group.members.map(m => <tr key={m.userId}><td><strong>{m.name}</strong><code>{short(m.userId)}</code></td><td>{m.role}</td><td><Badge muted={m.status !== 'active'}>{m.status}</Badge></td><td><div className="actions">{owner && m.status === 'pending' && ['approve', 'reject'].map(decision => <button disabled={busy} key={decision} onClick={() => run(() => api('POST', `/groups/${groupId}/members`, { userId: m.userId, decision }))}>{decision}</button>)}{owner && m.role !== 'owner' && m.status === 'active' && <button disabled={busy} className="danger" onClick={() => run(async () => setResult(await api('DELETE', `/groups/${groupId}/members/${m.userId}?mode=${mode}`)))}>Remove member</button>}</div></td></tr>)}</tbody></table></div>{!owner && <button className="button secondary" disabled={busy} onClick={() => run(() => api('POST', `/groups/${groupId}/leave`), 'You left the group. Its key has rotated.')}>Leave group</button>}{result && <div className="result"><strong>Revocation complete · v{result.currentVersion}</strong><span>{result.elapsedMs.toFixed(1)} ms · {result.filesReencrypted} files re-encrypted · {bytes(result.bytesProcessed)} processed</span></div>}</>}
            {tab === 'Keys & Versions' && status && <><div className="section-heading"><div><h2>Access evolves. History stays intact.</h2><p>Revocation creates a new key. Older files keep their version until migration.</p></div><button className="button" disabled={busy} onClick={() => run(async () => setResult(await api('POST', `/admin/groups/${groupId}/reencrypt`)))}>Run re-encryption ↗</button></div><div className="version-grid">{status.versions.map(v => <div className={`version-card ${v.purgedAt ? 'purged' : ''}`} key={v.version}><Badge muted={!!v.purgedAt}>v{v.version}</Badge><strong>{v.activeFiles}<small>active files</small></strong><span>{v.purgedAt ? 'Purged · key destroyed' : v.reason}</span><small>{new Date(v.createdAt).toLocaleString()}</small></div>)}</div><div className="panel threshold"><div><h3>Migration threshold</h3><p>Current v{status.currentVersion} − oldest in use v{status.oldestInUse} = {status.currentVersion - status.oldestInUse}</p></div><Badge>{status.triggerFires ? 'Migration queued' : `Threshold T = ${status.T}`}</Badge><progress max={status.T + 1} value={status.currentVersion - status.oldestInUse}/><small>Triggers when the difference exceeds T. {status.jobs.pending} pending · {status.jobs.done} completed jobs.</small></div>{result && <div className="result"><strong>{result.migrated} files migrated in {result.elapsedMs.toFixed(1)} ms</strong><span>Purged versions: {result.purgedVersions.join(', ') || 'none'}</span></div>}<p className="footnote">Key bytes are never displayed. Migration unpins old ciphertext on this node; it cannot erase copies held elsewhere.</p></>}
            {tab === 'Audit' && <><div className="section-heading"><div><h2>An independent record</h2><p>Read directly from the blockchain, using a read-only connection.</p></div><button className="button secondary" disabled={busy} onClick={() => run(async () => setAudit(await chain.audit(groupId)))}>Refresh audit</button></div><div className="audit-list">{audit.map((a, i) => <article key={i}><span className="audit-dot"/><div><h3>{a.event}</h3><code>{a.details}</code><small>Block {a.block} · {a.txHash}</small></div></article>)}</div></>}
            {tab === 'Inspector' && <><form className="inline-form panel" onSubmit={e => { e.preventDefault(); run(inspectRecord); }}><Field label="On-chain record ID" type="number" min="1" required value={recordInput} onChange={e => setRecordInput(e.target.value)}/><button className="button" disabled={busy}>Inspect record</button></form>{inspect && <><div className="inspect-grid"><section className="panel"><span className="eyebrow">01 / BLOCKCHAIN</span><h3>Public, verifiable metadata</h3><pre>{JSON.stringify(inspect, null, 2)}</pre></section><section className="panel"><span className="eyebrow">02 / IPFS</span><h3>Ciphertext only</h3><p>Format byte | 12-byte IV | ciphertext | 16-byte tag</p><pre>{cipher ? toHex(cipher.slice(0, 256)) : 'Ciphertext unavailable on this node'}</pre><p>Unreadable without the matching group key.</p></section><section className="panel"><span className="eyebrow">03 / PROXY</span><h3>Access and key custody</h3><p>The proxy received ciphertext on upload. It holds sealed group keys and sees plaintext in memory during migration.</p>{status ? <p>{status.versions.filter(v => !v.purgedAt).length} live key versions · {status.jobs.done} completed migrations</p> : <p>Key inventory is visible to the owner.</p>}<button className="button secondary" disabled={busy} onClick={() => run(() => receive(inspect.recordId, true))}>Decrypt here</button></section></div>{plaintext && <div className="panel"><h3>Decrypted on this device</h3><pre>{plaintext}</pre></div>}{stage && <div className="stage">{stage}</div>}<button className="button secondary" onClick={() => setTab('Attacker')}>Open security lab →</button></>}</>}
          </>}
        </>}
        {id && tab === 'Attacker' && <><div className="page-heading"><div><span className="eyebrow">TEST THE TRUST BOUNDARY</span><h1>Security lab<span className="title-dot">.</span></h1><p>Run as {id.name}. Switch to an outsider or revoked identity to test access.</p></div><Badge>Demo tools</Badge></div><div className="panel"><div className="three-cols"><Field label="Group ID" value={attackG} onChange={e => setAttackG(e.target.value)}/><Field label="Ciphertext CID" value={attackCid} onChange={e => setAttackCid(e.target.value)}/><Field label="Old key version" type="number" min="1" value={attackV} onChange={e => setAttackV(e.target.value)}/></div><div className="lab-actions">{[['cipher', 'Fetch public ciphertext'], ['key', 'Request current key'], ['old', 'Request old key'], ['cached', 'Decrypt with cached key'], ['replay', 'Replay request'], ['tamper', 'Tamper & decrypt']].map(([action, label]) => <button className="button secondary" disabled={busy || (!config?.demoMode && ['cipher', 'cached', 'tamper'].includes(action))} key={action} onClick={() => run(() => attack(action))}>{label}</button>)}</div>{attackResult && <pre role="status" className="lab-result">{attackResult}</pre>}</div><div className="panel caveat"><h3>Revocation has an honest limit.</h3><p>A removed member cannot request any group key. But a key and ciphertext they already copied can still decrypt old files. Re-encryption reduces availability on this node; it cannot recall someone else’s copies.</p></div></>}
      </main>
      <footer><div className="health">{['proxy', 'ipfs', 'chain'].map(service => <span key={service}><i className={health[service] ? 'online' : ''}/>{service}</span>)}</div><label className="cache-toggle"><input type="checkbox" checked={cache} onChange={e => { setCache(e.target.checked); setCacheEnabled(e.target.checked); }}/> Cache future group keys on this device</label><button onClick={() => setTab('Attacker')}>Security lab ↗</button><span>SecureFile / Local research demo</span></footer>
    </div>
  </div>;
}


