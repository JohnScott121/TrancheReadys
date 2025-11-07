import { parseISO, differenceInCalendarDays, isAfter } from 'date-fns';

const HR_COUNTRIES = new Set(['RU', 'CN', 'HK', 'AE', 'IN', 'IR']);

function toBand(score) {
  if (score >= 30) return 'High';
  if (score >= 15) return 'Medium';
  return 'Low';
}
function daysBetween(a, b) {
  return Math.abs(differenceInCalendarDays(parseISO(a), parseISO(b)));
}

export async function scoreAll(clients, txs, lookback) {
  const txByClient = new Map();
  const lbStart = parseISO(lookback.start);
  for (const t of txs) {
    const td = parseISO(t.date);
    if (isAfter(td, lbStart) || t.date === lookback.start) {
      if (!txByClient.has(t.client_id)) txByClient.set(t.client_id, []);
      txByClient.get(t.client_id).push(t);
    }
  }

  const results = [];
  for (const c of clients) {
    const reasons = [];
    let score = 0;

    // Profile
    const pep = String(c.pep_flag || '').toLowerCase() === 'true';
    const sanc = String(c.sanctions_flag || '').toLowerCase() === 'true';
    if (pep) {
      score += 20;
      reasons.push(r('profile', 'PEP flag', 20));
    }
    if (sanc) {
      score += 25;
      reasons.push(r('profile', 'Sanctions flag', 25));
    }

    if (c.kyc_last_reviewed_at) {
      const latest = parseISO(lookback.end);
      const kd = parseISO(c.kyc_last_reviewed_at);
      if (!isNaN(kd)) {
        const days = differenceInCalendarDays(latest, kd);
        if (days > 365) {
          score += 5;
          reasons.push(r('profile', 'Stale KYC > 12 months', 5));
        }
      }
    }

    const chan = (c.delivery_channel || '').toLowerCase();
    if (chan.includes('online')) {
      score += 3;
      reasons.push(r('profile', 'Online channel', 3));
    }

    const svc = (c.services || '').toLowerCase();
    if (svc.includes('remittance')) {
      score += 6;
      reasons.push(r('profile', 'Remittance service', 6));
    }
    if (svc.includes('property')) {
      score += 4;
      reasons.push(r('profile', 'Property service', 4));
    }

    const rc = (c.residency_country || '').toUpperCase();
    if (HR_COUNTRIES.has(rc)) {
      score += 8;
      reasons.push(r('profile', 'High-risk residency', 8));
    }

    // Behaviour last 18 months
    const txlist = (txByClient.get(c.client_id) || []).sort((a, b) => a.date.localeCompare(b.date));

    const cashIn = txlist.filter(
      (t) => t.direction === 'in' && t.method === 'cash' && t.currency === 'AUD' && t.amount >= 9600 && t.amount <= 9999
    );
    let structured = false;
    for (let i = 0; i < cashIn.length; i++) {
      const win = [cashIn[i]];
      for (let j = i + 1; j < cashIn.length; j++) {
        if (daysBetween(cashIn[i].date, cashIn[j].date) <= 7) win.push(cashIn[j]);
      }
      if (win.length >= 4) {
        structured = true;
        break;
      }
    }
    if (structured) {
      score += 12;
      reasons.push(r('behaviour', 'Structuring (≥4 cash deposits 9.6–9.999k within 7 days)', 12));
    }

    const intlHR = txlist.filter(
      (t) => t.direction === 'out' && HR_COUNTRIES.has(t.counterparty_country || '') && t.currency === 'AUD'
    );
    if (intlHR.length >= 2 && intlHR.some((t) => t.amount >= 20000)) {
      score += 10;
      reasons.push(r('behaviour', 'High-risk corridor transfers (≥2; one ≥ 20k)', 10));
    }

    const largeAU = txlist.filter(
      (t) => t.currency === 'AUD' && t.amount >= 100000 && (!t.counterparty_country || t.counterparty_country === 'AU')
    );
    if (largeAU.length >= 1) {
      score += 8;
      reasons.push(r('behaviour', 'Large domestic transfer ≥ 100k', 8));
    }

    results.push({
      client_id: c.client_id,
      score,
      band: toBand(score),
      reasons: reasons.map((x) => ({ type: 'reason', ...x }))
    });
  }

  return {
    scores: results,
    rulesMeta: {
      ruleset_id: 'dnfbp-2025.11',
      lookback,
      corridors: Array.from(HR_COUNTRIES),
      banding: { High: '>=30', Medium: '>=15', Low: '<15' }
    }
  };
}

function r(family, text, points) {
  return { family, text, points };
}
