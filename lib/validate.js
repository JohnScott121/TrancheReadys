// lib/validate.js
import { parseISO, isValid } from 'date-fns';

function req(v){ return v !== undefined && v !== null && String(v).trim() !== ''; }
function isAUD(a){ return String(a || '').toUpperCase() === 'AUD'; }
function isInOut(v){ v = String(v||'').toLowerCase(); return v === 'in' || v === 'out'; }

export function validateClients(rows) {
  const problems = [];
  let i = 1; // 1-based after header
  for (const r of rows) {
    const errs = [];
    if (!req(r.client_id)) errs.push('client_id is required');
    if (!req(r.full_name)) errs.push('full_name is required');
    if (req(r.dob)) {
      const d = parseISO(String(r.dob));
      if (!isValid(d)) errs.push('dob must be YYYY-MM-DD');
    }
    if (req(r.kyc_last_reviewed_at)) {
      const d = parseISO(String(r.kyc_last_reviewed_at));
      if (!isValid(d)) errs.push('kyc_last_reviewed_at must be YYYY-MM-DD');
    }
    if (errs.length) problems.push({ row: i, client_id: r.client_id || '', errors: errs });
    i++;
  }
  return problems;
}

export function validateTransactions(rows) {
  const problems = [];
  let i = 1;
  for (const r of rows) {
    const errs = [];
    if (!req(r.tx_id)) errs.push('tx_id is required');
    if (!req(r.client_id)) errs.push('client_id is required');
    if (!req(r.date) || !isValid(parseISO(String(r.date)))) errs.push('date must be YYYY-MM-DD');
    const amt = Number(r.amount);
    if (Number.isNaN(amt)) errs.push('amount must be a number');
    if (!req(r.currency)) errs.push('currency is required');
    if (!isInOut(r.direction)) errs.push('direction must be "in" or "out"');
    if (r.currency && !isAUD(r.currency)) errs.push('currency must be AUD for scoring rules');
    if (errs.length) problems.push({ row: i, tx_id: r.tx_id || '', errors: errs });
    i++;
  }
  return problems;
}
