const form = document.getElementById('uform');
const clientsInput = document.getElementById('clientsInput');
const txInput = document.getElementById('txInput');
const drop = document.getElementById('drop');
const progress = document.getElementById('progress');
const bar = progress?.querySelector('.bar');
const out = document.getElementById('out');

const summary = document.getElementById('summary');
const verifyUrlEl = document.getElementById('verifyUrl');
const copyVerify = document.getElementById('copyVerify');
const openVerify = document.getElementById('openVerify');
const downloadZip = document.getElementById('downloadZip');
const riskWrap = document.getElementById('riskWrap');
const riskBody = document.getElementById('riskBody');

const toastEl = document.getElementById('toast');
const submitBtn = document.getElementById('submitBtn');
const validateBtn = document.getElementById('validateBtn');

function toast(msg, ms = 2200) {
  toastEl.textContent = msg;
  toastEl.hidden = false;
  requestAnimationFrame(() => toastEl.classList.add('show'));
  setTimeout(() => {
    toastEl.classList.remove('show');
    setTimeout(() => (toastEl.hidden = true), 180);
  }, ms);
}
function esc(s) {
  return (s ?? '').toString().replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

if (drop) {
  const setHover = (v) => drop.setAttribute('data-hover', v ? 'true' : 'false');
  ['dragenter', 'dragover'].forEach((ev) =>
    drop.addEventListener(ev, (e) => {
      e.preventDefault();
      setHover(true);
    })
  );
  ['dragleave', 'drop'].forEach((ev) =>
    drop.addEventListener(ev, (e) => {
      e.preventDefault();
      if (ev === 'drop') handleDrop(e);
      setHover(false);
    })
  );
  drop.addEventListener('click', () => clientsInput?.click());
  drop.addEventListener('keydown', (e) => {
    if (e.key === ' ' || e.key === 'Enter') {
      e.preventDefault();
      clientsInput?.click();
    }
  });

  function handleDrop(e) {
    const files = [...(e.dataTransfer?.files || [])];
    const clients = files.find((f) => /\.csv$/i.test(f.name) && /clients?/i.test(f.name));
    const txs = files.find((f) => /\.csv$/i.test(f.name) && /(transactions?|transfers?)/i.test(f.name));
    if (clients) setFile(clientsInput, clients);
    if (txs) setFile(txInput, txs);
    if (!clients || !txs) toast('Need both Clients.csv and Transactions.csv');
  }
  function setFile(input, file) {
    const dt = new DataTransfer();
    dt.items.add(file);
    input.files = dt.files;
  }
}

validateBtn?.addEventListener('click', () => run('/api/validate'));
form?.addEventListener('submit', (e) => {
  e.preventDefault();
  run('/upload', true);
});

async function run(url, isGenerate = false) {
  try {
    if (!clientsInput.files[0] || !txInput.files[0]) {
      toast('Select both files');
      return;
    }
    if (!/\.csv$/i.test(clientsInput.files[0].name) || !/\.csv$/i.test(txInput.files[0].name)) {
      toast('Files must be .csv');
      return;
    }

    if (isGenerate) submitBtn.classList.add('loading');
    out.textContent = '';
    summary.hidden = true;
    riskWrap.hidden = true;
    progress.hidden = false;
    setBar(10);

    const fd = new FormData();
    fd.append('clients', clientsInput.files[0]);
    fd.append('transactions', txInput.files[0]);

    setBar(40);
    const res = await fetch(url, { method: 'POST', body: fd, headers: { 'X-Requested-With': 'fetch' } });
    const text = await res.text();
    let data = {};
    try {
      data = text ? JSON.parse(text) : {};
    } catch {}

    setBar(80);
    if (!res.ok) {
      out.textContent = JSON.stringify({ ok: false, status: res.status, body: data || text }, null, 2);
      throw new Error((data && data.error) || `Request failed (${res.status})`);
    }

    if (isGenerate) {
      verifyUrlEl.textContent = data.verify_url;
      openVerify.href = data.verify_url;
      downloadZip.href = data.download_url;
      summary.hidden = false;

      renderRisk(data.risk || []);
      riskWrap.hidden = false;
      out.textContent = '';
      toast('Evidence ready');
    } else {
      out.textContent = JSON.stringify(data, null, 2);
      toast('Validated');
    }
    setBar(100);
  } catch (err) {
    toast('Error: ' + (err.message || 'failed'));
  } finally {
    submitBtn.classList.remove('loading');
    setTimeout(() => {
      progress.hidden = true;
      setBar(0);
    }, 400);
  }
}

function setBar(p) {
  if (bar) bar.style.width = `${Math.max(0, Math.min(100, p))}%`;
}

function renderRisk(items) {
  riskBody.innerHTML = '';
  const frag = document.createDocumentFragment();
  for (const item of items) {
    const band = String(item.band || 'Low').toLowerCase();
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span class="mono">${esc(item.client_id || '—')}</span></td>
      <td><span class="badge ${band === 'high' ? 'high' : band === 'medium' ? 'med' : 'low'}">${esc(item.band || 'Low')}</span></td>
      <td>${String(item.score ?? 0)}</td>
      <td>
        ${Array.isArray(item.reasons) && item.reasons.length ? `
          <details><summary>${item.reasons.length} reason${item.reasons.length === 1 ? '' : 's'}</summary>
          <div class="reason-list">
            ${item.reasons.map(r => `<div class="reason"><span class="tag">${esc(r.family)} +${esc(r.points)}</span><span>${esc(r.text)}</span></div>`).join('')}
          </div></details>` : '<span class="muted">—</span>'}
      </td>`;
    frag.appendChild(tr);
  }
  riskBody.appendChild(frag);
}

copyVerify?.addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(verifyUrlEl.textContent);
    toast('Verify link copied');
  } catch {
    toast('Copy failed');
  }
});
