export const LIVE_HTML: string = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pool activity</title><style>
:root{color-scheme:light dark;--bg:#f5f6f8;--panel:#fff;--text:#202630;--muted:#536173;--line:#ccd3dd;--accent:#245ac7;--you:#e7efff}
@media(prefers-color-scheme:dark){:root{--bg:#141820;--panel:#1e2530;--text:#eef1f6;--muted:#b0bed0;--line:#455164;--accent:#8ab4ff;--you:#263c60}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 system-ui,sans-serif}main{max-width:960px;margin:auto;padding:20px}h1{font-size:1.8rem;margin:0;overflow-wrap:anywhere}h2{font-size:1.15rem;margin:0 0 12px}section{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:16px;margin:16px 0}#status{color:var(--muted);min-height:1.5em}form{display:flex;flex-wrap:wrap;gap:8px;align-items:center}input,button{font:inherit;padding:8px;border:1px solid var(--line);border-radius:4px;background:var(--panel);color:var(--text)}input{min-width:0;flex:1}button{cursor:pointer}progress{width:100%;height:22px;accent-color:var(--accent)}.counts{display:flex;flex-wrap:wrap;gap:8px 24px;margin:12px 0}.table{overflow-x:auto}table{width:100%;border-collapse:collapse;text-align:left;font-size:.9rem}th,td{padding:8px 6px;border-bottom:1px solid var(--line)}td:first-child{overflow-wrap:anywhere}tr.you{background:var(--you)}ol{padding-left:22px}li{padding:8px 0;overflow-wrap:anywhere}time{color:var(--muted);font-size:.85rem;display:block}@media(max-width:480px){main{padding:12px}section{padding:12px}th,td{padding:6px 4px;font-size:.8rem}}
</style></head><body><main>
<h1 id="project">Pool activity</h1><p id="status" role="status" aria-live="polite"></p>
<form id="login"><label for="token">Access token</label><input id="token" type="password" autocomplete="off" spellcheck="false" required><button>Connect</button></form>
<section><h2>Progress <span id="percent">0%</span></h2><progress id="progress" max="100" value="0" aria-label="Functions done"></progress><div id="totals" class="counts"></div></section>
<section><h2>Results</h2><div id="results" class="counts"></div><p id="throughput"></p></section>
<section><h2>People</h2><div class="table"><table><thead><tr><th>Name</th><th>Analyses</th><th>Checks</th><th>Trusted</th><th>Working</th></tr></thead><tbody id="people"></tbody></table></div></section>
<section><h2>Recent activity</h2><ol id="recent"></ol></section>
</main><script>
(() => {
  const get = id => document.getElementById(id);
  const params = new URLSearchParams(location.hash.slice(1));
  let token = params.get('token') || '';
  if (location.hash) history.replaceState(null, '', location.pathname + location.search);
  if (!token) { try { token = sessionStorage.getItem('rea-pool-token') || ''; } catch {} }
  const remember = () => { try { sessionStorage.setItem('rea-pool-token', token); } catch {} };
  if (token) remember();
  get('login').hidden = Boolean(token);
  const element = (tag, text) => { const node = document.createElement(tag); node.textContent = String(text); return node; };
  const counts = (id, entries) => { get(id).replaceChildren(...entries.map(([label, count]) => element('span', count + ' ' + label))); };
  const render = data => {
    get('project').textContent = data.project;
    document.title = data.project + ' — Pool activity';
    get('percent').textContent = data.totals.percentDone + '%';
    get('progress').value = data.totals.percentDone;
    counts('totals', [['done', data.totals.done], ['in progress', data.totals.inProgress], ['waiting', data.totals.waiting]]);
    counts('results', [['trusted', data.results.trusted], ['pending', data.results.pending], ['hints', data.results.hints], ['rejected', data.results.rejected]]);
    get('throughput').textContent = data.throughputPerHour + ' analyses and checks in the last hour';
    get('people').replaceChildren(...data.people.map(person => {
      const row = document.createElement('tr');
      if (person.you) row.className = 'you';
      [person.name + (person.you ? ' (you)' : ''), person.analyses, person.checks, person.trusted, person.working ? '● Yes' : '—'].forEach(value => row.append(element('td', value)));
      return row;
    }));
    get('recent').replaceChildren(...data.recent.map(event => {
      const item = document.createElement('li');
      item.append(element('span', event.who + ' ' + event.what));
      const time = element('time', new Date(event.at).toLocaleString());
      time.dateTime = event.at; item.append(time); return item;
    }));
  };
  let busy = false;
  const poll = async () => {
    if (!token || busy) return;
    busy = true;
    const currentToken = token;
    try {
      const response = await fetch('/activity', { headers: { Authorization: 'Bearer ' + currentToken }, cache: 'no-store', signal: AbortSignal.timeout(10000) });
      if (currentToken !== token) return;
      if (response.status === 401) {
        get('status').textContent = 'token not recognised'; get('login').hidden = false; return;
      }
      if (!response.ok) throw new Error('Request failed');
      const data = await response.json();
      if (currentToken !== token) return;
      render(data); get('status').textContent = 'Live · updates every 3 seconds'; get('login').hidden = true;
    } catch { if (currentToken === token) get('status').textContent = 'reconnecting...'; }
    finally { busy = false; }
  };
  get('login').addEventListener('submit', event => {
    event.preventDefault(); token = get('token').value.trim(); get('token').value = '';
    if (!token) return;
    remember(); get('login').hidden = true; void poll();
  });
  void poll(); setInterval(poll, 3000);
})();
</script></body></html>`;
