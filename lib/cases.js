import { parseISO } from 'date-fns';

const HR_COUNTRIES = new Set(['RU', 'CN', 'HK', 'AE', 'IN', 'IR']);

export function buildCases(txs, _lookback) {
  const cases = [];
  const byClient = new Map();
  for (const t of txs) {
    if (!byClient.has(t.client_id)) byClient.set(t.client_id, []);
    byClient.get(t.client_id).push(t);
  }

  for (const [client_id, list] of byClient) {
    const sorted = list.slice().sort((a, b) => a.date.localeCompare(b.date));

    const struct = sorted.filter(
      (t) => t.direction === 'in' && t.method === 'cash' && t.currency === 'AUD' && t.amount >= 9600 && t.amount <= 9999
    );
    if (struct.length >= 4) {
      for (let i = 0; i < struct.length; i++) {
        const base = parseISO(struct[i].date).getTime();
        const win = struct.filter((t) => Math.abs(parseISO(t.date).getTime() - base) <= 7 * 24 * 3600 * 1000);
        if (win.length >= 4) {
          cases.push({
            type: 'structuring',
            client_id,
            window_start: struct[i].date,
            window_count: win.length,
            sample: win.slice(0, 5).map((t) => t.tx_id)
          });
          break;
        }
      }
    }

    const intl = sorted.filter(
      (t) => t.direction === 'out' && HR_COUNTRIES.has(t.counterparty_country || '') && t.currency === 'AUD'
    );
    if (intl.length >= 2 && intl.some((t) => t.amount >= 20000)) {
      cases.push({
        type: 'high_risk_corridor',
        client_id,
        count: intl.length,
        countries: Array.from(new Set(intl.map((t) => t.counterparty_country))).join(','),
        max_amount: Math.max(...intl.map((t) => t.amount))
      });
    }

    const large = sorted.filter(
      (t) => t.currency === 'AUD' && t.amount >= 100000 && (!t.counterparty_country || t.counterparty_country === 'AU')
    );
    if (large.length) {
      cases.push({
        type: 'large_domestic',
        client_id,
        count: large.length,
        max_amount: Math.max(...large.map((t) => t.amount))
      });
    }
  }
  return cases;
}
