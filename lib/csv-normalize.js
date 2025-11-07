import { parseISO, isValid, subMonths, max as maxDate } from 'date-fns';

// tolerant, case-insensitive key mapping
const CLIENT_KEYS = {
  client_id: ['client_id', 'clientid', 'id'],
  full_name: ['full_name', 'name', 'client_name'],
  dob: ['dob', 'date_of_birth'],
  residency_country: ['residency_country', 'country', 'residence_country'],
  delivery_channel: ['delivery_channel', 'channel'],
  services: ['services', 'service'],
  pep_flag: ['pep', 'pep_flag'],
  sanctions_flag: ['sanctions', 'sanctions_flag'],
  kyc_last_reviewed_at: ['kyc_last_reviewed_at', 'kyc_date', 'kyc_last_review', 'kyc_reviewed_at']
};

const TX_KEYS = {
  tx_id: ['tx_id', 'id', 'transaction_id'],
  client_id: ['client_id', 'clientid'],
  date: ['date', 'txn_date', 'transaction_date'],
  amount: ['amount', 'amt', 'value'],
  currency: ['currency', 'ccy'],
  direction: ['direction', 'flow'], // in/out
  method: ['method', 'payment_method', 'pay_method'], // cash, wire, etc
  counterparty_name: ['counterparty', 'counterparty_name', 'beneficiary'],
  counterparty_country: ['counterparty_country', 'cp_country', 'country'],
  matter_id: ['matter_id', 'matter', 'file_id', 'case_id']
};

function mapKeys(row, map) {
  const out = {};
  const lower = Object.fromEntries(Object.entries(row).map(([k, v]) => [k.toLowerCase().trim(), v]));
  for (const [target, synonyms] of Object.entries(map)) {
    const hit = synonyms.find((s) => s in lower);
    out[target] = lower[hit] ?? '';
  }
  return out;
}

export function normalizeClients(rows) {
  const mapped = rows.map((r) => mapKeys(r, CLIENT_KEYS));
  // lightweight header map for program.html
  const clientHeaderMap = Object.fromEntries(Object.entries(CLIENT_KEYS).map(([k, v]) => [k, v[0]]));
  // coerce flags/dates
  const clients = mapped.map((c) => ({
    client_id: String(c.client_id || '').trim(),
    full_name: String(c.full_name || '').trim(),
    dob: String(c.dob || '').trim(),
    residency_country: String(c.residency_country || '').trim().toUpperCase(),
    delivery_channel: String(c.delivery_channel || '').trim(),
    services: String(c.services || '').trim(),
    pep_flag: String(c.pep_flag || '').trim(),
    sanctions_flag: String(c.sanctions_flag || '').trim(),
    kyc_last_reviewed_at: String(c.kyc_last_reviewed_at || '').trim()
  }));
  return { clients, clientHeaderMap };
}

export function normalizeTransactions(rows) {
  const mapped = rows.map((r) => mapKeys(r, TX_KEYS));

  let latest = null;
  const txs = [];
  const rejects = [];

  for (const t of mapped) {
    const d = parseISO(String(t.date || '').trim());
    const amt = Number(t.amount);
    const ok =
      String(t.client_id || '').trim() &&
      isValid(d) &&
      !Number.isNaN(amt) &&
      String(t.currency || '').trim();

    if (!ok) {
      rejects.push({ tx_id: t.tx_id || '', reason: 'missing/invalid fields' });
      continue;
    }

    latest = latest ? maxDate(latest, d) : d;
    txs.push({
      tx_id: String(t.tx_id || '').trim(),
      client_id: String(t.client_id || '').trim(),
      date: String(t.date || '').trim(),
      amount: amt,
      currency: String(t.currency || '').trim().toUpperCase(),
      direction: String(t.direction || '').trim().toLowerCase(), // in/out
      method: String(t.method || '').trim().toLowerCase(),
      counterparty_name: String(t.counterparty_name || '').trim(),
      counterparty_country: String(t.counterparty_country || '').trim().toUpperCase(),
      matter_id: String(t.matter_id || '').trim()
    });
  }

  const end = latest ? latest.toISOString().slice(0, 10) : new Date().toISOString().slice(0, 10);
  const start = subMonths(new Date(end), 18).toISOString().slice(0, 10);
  const txHeaderMap = Object.fromEntries(Object.entries(TX_KEYS).map(([k, v]) => [k, v[0]]));

  return { txs, rejects, lookback: { start, end }, txHeaderMap };
}
