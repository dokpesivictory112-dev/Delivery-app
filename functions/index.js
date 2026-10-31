// Fers Innova - delivery confirmation, server side.
//
// Customers never touch the database directly any more. The page calls these
// four functions. Each one checks invoice + phone on the server, so nobody can
// skip the page and read or change an order by guessing invoice numbers.

const {onCall, HttpsError} = require('firebase-functions/v2/https');
const {initializeApp} = require('firebase-admin/app');
const {getFirestore, FieldValue} = require('firebase-admin/firestore');
const crypto = require('crypto');

initializeApp();
const db = getFirestore();

// Europe is the closest region to Nigeria that Cloud Functions offers.
// The page must use the same region name (it does).
const OPTS = {region: 'europe-west1', maxInstances: 10, cors: true};

// ---------- Limits (all per 1 hour) ----------
const WINDOW_MS = 60 * 60 * 1000;
const MAX_PAIR_FAILS = 5;   // same device + same invoice
const MAX_INV_FAILS = 12;   // anyone, same invoice (stops spread-out guessing)
const MAX_IP_FAILS = 40;    // same device, any invoice (high, because phone networks share addresses)

// ---------- Small helpers ----------
function normalizeInvoice(raw){
  return String(raw == null ? '' : raw).trim().toUpperCase().replace(/^INV/, '');
}

function validInvoiceId(inv){
  // Also protects the database path: no slashes or odd characters allowed.
  return /^[A-Z0-9-]{1,30}$/.test(inv);
}

function normalizePhone(p){
  let digits = String(p == null ? '' : p).replace(/[^0-9]/g, '');
  if(digits.startsWith('234')) digits = digits.slice(3);
  if(digits.startsWith('0')) digits = digits.slice(1);
  return digits;
}

// Words that appear in many business names. They never count as a match.
const STOP_WORDS = new Set(['ltd','limited','enterprise','enterprises','nigeria','nig','company','and','the',
  'mr','mrs','miss','ms','dr','chief','prof','stores','store','shop','global','venture','ventures','services','group']);

function nameWords(s){
  return String(s == null ? '' : s)
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, ' ')
    .split(' ')
    .filter(w => w.length >= 3 && !STOP_WORDS.has(w));
}

// One word of the registered name is enough (first name, surname, either).
// Capital letters and extra words don't matter. Both names the import saves are accepted.
function nameMatches(typed, order){
  const t = nameWords(typed);
  if(!t.length) return false;
  const stored = new Set([].concat(nameWords(order.clientName), nameWords(order.organizationName), nameWords(order.client)));
  return t.some(w => stored.has(w));
}

function sha(s){
  return crypto.createHash('sha256').update(String(s)).digest('hex').slice(0, 32);
}

function clientAddress(request){
  const raw = request.rawRequest;
  const fwd = raw && raw.headers && raw.headers['x-forwarded-for'];
  const first = fwd ? String(fwd).split(',')[0].trim() : '';
  return first || (raw && raw.ip) || 'unknown';
}

function str(v, max){
  return String(v == null ? '' : v).trim().slice(0, max);
}

function isoDate(v){
  const s = String(v || '').trim();
  return /^\d{4}-\d{2}-\d{2}$/.test(s) ? s : '';
}

// Earliest day a customer may choose: the later of the admin start date and
// tomorrow (Nigeria time, UTC+1), so nobody can book the same day they ask.
function earliestDay(portal, now){
  const lagos = new Date((now || new Date()).getTime() + 60 * 60 * 1000);
  lagos.setUTCDate(lagos.getUTCDate() + 1);
  const tomorrow = lagos.toISOString().slice(0, 10);
  return laterDate(portal && portal.pickupStartDate, tomorrow);
}

function laterDate(a, b){
  a = a || ''; b = b || '';
  return a > b ? a : b; // YYYY-MM-DD strings compare correctly as text
}

// ---------- Rate limiting ----------
async function readCount(key){
  const snap = await db.collection('rateLimits').doc(key).get();
  if(!snap.exists) return 0;
  const d = snap.data();
  if(!d.start || Date.now() - d.start > WINDOW_MS) return 0;
  return d.count || 0;
}

async function bump(key){
  const ref = db.collection('rateLimits').doc(key);
  await db.runTransaction(async tx => {
    const snap = await tx.get(ref);
    const now = Date.now();
    const d = snap.exists ? snap.data() : null;
    if(!d || !d.start || now - d.start > WINDOW_MS){
      tx.set(ref, {count: 1, start: now});
    } else {
      tx.update(ref, {count: (d.count || 0) + 1});
    }
  });
}

function limitKeys(request, inv){
  const ip = sha(clientAddress(request));
  return {
    pair: 'p_' + sha(ip + '|' + inv),
    inv: 'i_' + sha(inv),
    ip: 'a_' + ip
  };
}

async function assertNotBlocked(keys){
  const [pair, inv, ip] = await Promise.all([readCount(keys.pair), readCount(keys.inv), readCount(keys.ip)]);
  if(pair >= MAX_PAIR_FAILS || inv >= MAX_INV_FAILS || ip >= MAX_IP_FAILS){
    throw new HttpsError('resource-exhausted', 'TOO_MANY');
  }
}

async function recordFailure(keys){
  await Promise.all([bump(keys.pair), bump(keys.inv), bump(keys.ip)]);
}

// ---------- Core check: invoice + phone ----------
async function loadPortal(){
  const snap = await db.collection('settings').doc('portal').get();
  return snap.exists ? snap.data() : {};
}

// Returns {inv, ref, order, portal}. Throws a generic error on any mismatch,
// so a wrong invoice, a wrong phone and a wrong name all look exactly the same to an attacker.
async function verifyOrder(request, invRaw, phoneRaw, nameRaw){
  const inv = normalizeInvoice(invRaw);
  const portal = await loadPortal();
  if(portal.open === false) throw new HttpsError('failed-precondition', 'PORTAL_CLOSED');

  if(!validInvoiceId(inv) || !normalizePhone(phoneRaw) || !String(nameRaw == null ? '' : nameRaw).trim()){
    throw new HttpsError('invalid-argument', 'BAD_INPUT');
  }
  const keys = limitKeys(request, inv);
  await assertNotBlocked(keys);

  const ref = db.collection('orders').doc(inv);
  const snap = await ref.get();
  const order = snap.exists ? snap.data() : null;
  const stored = order ? normalizePhone(order.phone || '') : '';
  const typed = normalizePhone(phoneRaw);
  if(!order || !stored || stored !== typed || !nameMatches(nameRaw, order)){
    await recordFailure(keys);
    throw new HttpsError('not-found', 'NO_MATCH');
  }
  return {inv, ref, order, portal};
}

// Only what the customer needs to see. Never the stored phone number.
function publicOrder(inv, o, portal){
  return {
    inv,
    invoiceNumber: o.invoiceNumber || inv,
    clientName: o.clientName || o.client || '',
    items: Array.isArray(o.items) ? o.items.map(i => ({name: i.name, qty: i.qty, amt: i.amt})) : [],
    total: o.total == null ? null : o.total,
    balance: Number(o.balance) || 0,
    status: o.status || 'pending',
    locationType: o.locationType || '',
    recipientName: o.recipientName || '',
    recipientPhone: o.recipientPhone || '',
    area: o.area || '',
    landmark: o.landmark || '',
    street: o.street || '',
    state: o.state || '',
    pickupPersonName: o.pickupPersonName || '',
    pickupPersonPhone: o.pickupPersonPhone || '',
    pickupDate: o.pickupDate || '',
    pairedInvoice: o.pairedInvoice || '',
    minPickup: earliestDay(portal)
  };
}

// ---------- Function 1: look up an order ----------
exports.lookupOrder = onCall(OPTS, async request => {
  const d = request.data || {};
  const {inv, order, portal} = await verifyOrder(request, d.invoice, d.phone, d.name);
  return publicOrder(inv, order, portal);
});

// ---------- Function 2: check a paired invoice ----------
exports.verifyPair = onCall(OPTS, async request => {
  const d = request.data || {};
  const {inv, order} = await verifyOrder(request, d.invoice, d.phone, d.name);
  return {ok: true, inv, clientName: order.clientName || order.client || ''};
});

// ---------- Function 3: "something's wrong with my order" ----------
exports.flagOrder = onCall(OPTS, async request => {
  const d = request.data || {};
  const {ref} = await verifyOrder(request, d.invoice, d.phone, d.name);
  await db.runTransaction(async tx => {
    const snap = await tx.get(ref);
    const status = (snap.data() || {}).status || 'pending';
    if(status !== 'pending') throw new HttpsError('failed-precondition', 'LOCKED');
    tx.update(ref, {flagged: true, updatedAt: FieldValue.serverTimestamp()});
  });
  return {ok: true};
});

// ---------- Function 4: save delivery details ----------
const LABELS = {
  locationType: 'Delivery type', recipientName: 'Name', recipientPhone: 'Phone',
  area: 'Area', landmark: 'Landmark', street: 'Street', state: 'State',
  pickupPersonName: 'Pickup person', pickupPersonPhone: 'Pickup phone',
  pickupDate: 'Day', pairedInvoice: 'Paired invoice'
};
const LOC_NAMES = {benin: 'Benin City', outside: 'Park delivery', pickup: 'Pickup'};

function describeChanges(before, after){
  const show = (k, v) => (k === 'locationType' ? (LOC_NAMES[v] || v) : v) || '(empty)';
  const out = [];
  for(const k in LABELS){
    if(!(k in after)) continue;
    const b = before[k] == null ? '' : String(before[k]);
    const a = after[k] == null ? '' : String(after[k]);
    if(b !== a) out.push(`${LABELS[k]}: ${show(k, b)} → ${show(k, a)}`);
  }
  return out.join('; ').slice(0, 400);
}

function chooseDay(value, minDay){
  const day = isoDate(value);
  if(!day) throw new HttpsError('invalid-argument', 'BAD_INPUT:Please choose the day.');
  if(minDay && day < minDay){
    throw new HttpsError('invalid-argument', 'BAD_INPUT:That day is not available. Please choose ' + minDay + ' or a later day.');
  }
  return day;
}

function cleanDetails(input, minPickup){
  const t = input && input.locationType;
  if(!['benin', 'outside', 'pickup'].includes(t)) throw new HttpsError('invalid-argument', 'BAD_INPUT:Choose how the order will reach you.');
  const p = {locationType: t};
  const need = (val, label) => { if(!val) throw new HttpsError('invalid-argument', 'BAD_INPUT:Please fill in ' + label + '.'); return val; };

  if(t === 'benin'){
    p.recipientName = need(str(input.recipientName, 120), 'the recipient name');
    p.recipientPhone = need(str(input.recipientPhone, 30), 'the recipient phone number');
    p.area = need(str(input.area, 120), 'the area or town');
    p.landmark = need(str(input.landmark, 200), 'a landmark or description');
    p.street = str(input.street, 200) || '-';
    p.pickupDate = chooseDay(input.pickupDate, minPickup);
  } else if(t === 'outside'){
    p.recipientName = need(str(input.recipientName, 120), 'the recipient name');
    p.recipientPhone = need(str(input.recipientPhone, 30), 'the recipient phone number');
    p.state = need(str(input.state, 80), 'the state');
    p.area = need(str(input.area, 120), 'the area');
    p.pickupDate = chooseDay(input.pickupDate, minPickup);
  } else {
    p.pickupPersonName = need(str(input.pickupPersonName, 120), 'the pickup person name');
    p.pickupPersonPhone = need(str(input.pickupPersonPhone, 30), 'the pickup person phone number');
    p.pickupDate = chooseDay(input.pickupDate, minPickup);
  }
  return p;
}

exports.submitDelivery = onCall(OPTS, async request => {
  const d = request.data || {};
  const {inv, ref, portal} = await verifyOrder(request, d.invoice, d.phone, d.name);

  // Optional paired invoice: the other customer's phone must match too.
  let pairedInvoice = '';
  if(d.pairedInvoice){
    const pairInv = normalizeInvoice(d.pairedInvoice);
    if(pairInv === inv) throw new HttpsError('invalid-argument', 'BAD_INPUT:An invoice can\'t be paired with itself.');
    const pair = await verifyOrder(request, d.pairedInvoice, d.pairedPhone, d.pairedName);
    pairedInvoice = pair.inv;
  }

  await db.runTransaction(async tx => {
    // Read again inside the transaction, so a pack click that lands at the
    // same moment can't slip a customer change through.
    const snap = await tx.get(ref);
    if(!snap.exists) throw new HttpsError('not-found', 'NO_MATCH');
    const o = snap.data();

    if((o.status || 'pending') !== 'pending') throw new HttpsError('failed-precondition', 'LOCKED');
    if(Number(o.balance) > 0) throw new HttpsError('failed-precondition', 'BALANCE_OWING');

    const minPickup = earliestDay(portal);
    const details = cleanDetails(d.details, minPickup);
    if(pairedInvoice) details.pairedInvoice = pairedInvoice;

    const update = Object.assign({}, details, {updatedAt: FieldValue.serverTimestamp()});

    // A change after a first submission raises the alert Fers sees on the admin page.
    if(o.locationType){
      const summary = describeChanges(o, details);
      if(summary){
        update.customerChangedAt = FieldValue.serverTimestamp();
        update.changeAcknowledged = false;
        update.changeSummary = summary;
      }
    }
    tx.update(ref, update);
  });

  return {ok: true};
});

// Exposed only when testing outside Firebase. Never exported when deployed,
// so Firebase doesn't mistake it for a function.
if(process.env.FERS_FUNCTIONS_TEST === '1'){
  exports._test = {normalizeInvoice, validInvoiceId, normalizePhone, nameWords, nameMatches, laterDate, earliestDay, describeChanges, cleanDetails, publicOrder};
    }
