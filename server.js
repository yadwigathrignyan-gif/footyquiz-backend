require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const Razorpay = require('razorpay');
const { createClient } = require('@supabase/supabase-js');

const app = express();

// ─── MIDDLEWARE ──────────────────────────────────────────────────────────────
app.use(cors({
  origin: [
    process.env.FRONTEND_URL,
    'http://localhost:3000',
    'http://127.0.0.1:5500', // live server local dev
  ],
  methods: ['GET', 'POST'],
  credentials: true,
}));
app.use(express.json());

// ─── CLIENTS ─────────────────────────────────────────────────────────────────
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ─── HELPERS ─────────────────────────────────────────────────────────────────
function getCurrentRound() {
  const now = new Date();
  return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
}

function getRoundLabel() {
  const now = new Date();
  return now.toLocaleString('en-AU', { month: 'long', year: 'numeric' });
}

// ─── HEALTH CHECK ────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ─── ROUTE 1: Create Razorpay Order ─────────────────────────────────────────
// Called when user clicks "Pay $10 AUD"
// Returns an order_id that the frontend uses to open Razorpay checkout
app.post('/api/create-order', async (req, res) => {
  try {
    const { name, email, state, team } = req.body;

    // Basic validation
    if (!name || !email || !state || !team) {
      return res.status(400).json({ error: 'All fields are required.' });
    }
    if (!email.includes('@')) {
      return res.status(400).json({ error: 'Invalid email address.' });
    }

    const round = getCurrentRound();

    // Check if this email has already entered this round
    const { data: existing } = await supabase
      .from('entries')
      .select('id')
      .eq('email', email.toLowerCase().trim())
      .eq('round', round)
      .single();

    if (existing) {
      return res.status(409).json({
        error: 'You have already entered this month\'s round. One entry per person per round.'
      });
    }

    // Create Razorpay order
    const order = await razorpay.orders.create({
      amount: parseInt(process.env.ENTRY_AMOUNT_AUD_CENTS),
      currency: process.env.ENTRY_CURRENCY || 'AUD',
      receipt: `fq_${round}_${Date.now()}`,
      notes: {
        name: name.trim(),
        email: email.toLowerCase().trim(),
        state,
        team,
        round,
      },
    });

    // Store a pending entry in Supabase
    await supabase.from('entries').insert({
      razorpay_order_id: order.id,
      name: name.trim(),
      email: email.toLowerCase().trim(),
      state,
      team,
      round,
      status: 'pending',
      created_at: new Date().toISOString(),
    });

    res.json({
      order_id: order.id,
      amount: order.amount,
      currency: order.currency,
      key: process.env.RAZORPAY_KEY_ID,
      name,
      email,
      round_label: getRoundLabel(),
    });

  } catch (err) {
    console.error('create-order error:', err);
    res.status(500).json({ error: 'Failed to create payment order. Please try again.' });
  }
});

// ─── ROUTE 2: Verify Payment ─────────────────────────────────────────────────
// Called after Razorpay checkout succeeds
// Verifies signature cryptographically — this is critical for security
app.post('/api/verify-payment', async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return res.status(400).json({ error: 'Missing payment verification data.' });
    }

    // Verify signature using HMAC SHA256
    const body = razorpay_order_id + '|' + razorpay_payment_id;
    const expectedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(body)
      .digest('hex');

    if (expectedSignature !== razorpay_signature) {
      console.warn('Signature mismatch for order:', razorpay_order_id);
      return res.status(400).json({ error: 'Payment verification failed. Possible fraud attempt.' });
    }

    // Payment is genuine — update entry status to paid
    const { data: entries, error } = await supabase
      .from('entries')
      .update({
        razorpay_payment_id,
        razorpay_signature,
        status: 'paid',
        paid_at: new Date().toISOString(),
      })
      .eq('razorpay_order_id', razorpay_order_id)
      .select();

    const entry = entries && entries[0];

    if (error) {
      console.error('Supabase update error:', error);
      return res.status(500).json({ error: 'Payment verified but failed to update record.' });
    }

    res.json({
      success: true,
      entry_id: entry.id,
      message: 'Payment verified. Quiz unlocked!',
    });

  } catch (err) {
    console.error('verify-payment error:', err);
    res.status(500).json({ error: 'Verification failed. Please contact support.' });
  }
});

// ─── ROUTE 3: Submit Quiz Score ───────────────────────────────────────────────
// Called when user completes the quiz
app.post('/api/submit-score', async (req, res) => {
  try {
    const { entry_id, score, time_seconds, answers } = req.body;

    if (!entry_id || score === undefined || !time_seconds) {
      return res.status(400).json({ error: 'Missing score data.' });
    }

    // Validate score range
    if (score < 0 || score > 15) {
      return res.status(400).json({ error: 'Invalid score.' });
    }

    // Check entry exists and is paid
    const { data: entry } = await supabase
      .from('entries')
      .select('*')
      .eq('id', entry_id)
      .eq('status', 'paid')
      .single();

    if (!entry) {
      return res.status(404).json({ error: 'Entry not found or payment not confirmed.' });
    }

    // Check score not already submitted (prevent double submission)
    if (entry.score !== null) {
      return res.status(409).json({ error: 'Score already submitted for this entry.' });
    }

    // Save score
    const { error } = await supabase
      .from('entries')
      .update({
        score,
        time_seconds,
        answers: JSON.stringify(answers),
        status: 'completed',
        completed_at: new Date().toISOString(),
      })
      .eq('id', entry_id);

    if (error) {
      return res.status(500).json({ error: 'Failed to save score.' });
    }

    // Get current rank
    const { data: betterEntries } = await supabase
      .from('entries')
      .select('id')
      .eq('round', entry.round)
      .eq('status', 'completed')
      .or(`score.gt.${score},and(score.eq.${score},time_seconds.lt.${time_seconds})`);

    const rank = (betterEntries?.length || 0) + 1;

    res.json({ success: true, rank, score, time_seconds });

  } catch (err) {
    console.error('submit-score error:', err);
    res.status(500).json({ error: 'Failed to submit score.' });
  }
});

// ─── ROUTE 4: Get Leaderboard ─────────────────────────────────────────────────
// Public — returns top 50 for current round
app.get('/api/leaderboard', async (req, res) => {
  try {
    const round = req.query.round || getCurrentRound();
    const stateFilter = req.query.state;

    let query = supabase
      .from('entries')
      .select('name, state, team, score, time_seconds, completed_at')
      .eq('round', round)
      .eq('status', 'completed')
      .order('score', { ascending: false })
      .order('time_seconds', { ascending: true })
      .limit(50);

    if (stateFilter && stateFilter !== 'all') {
      query = query.eq('state', stateFilter);
    }

    const { data, error } = await query;

    if (error) {
      return res.status(500).json({ error: 'Failed to fetch leaderboard.' });
    }

    // Mask last name for privacy (e.g. "Jake Thompson" → "Jake T.")
    const masked = (data || []).map((e, i) => ({
      rank: i + 1,
      name: maskName(e.name),
      state: e.state,
      team: e.team,
      score: e.score,
      time_seconds: e.time_seconds,
    }));

    res.json({
      round,
      round_label: getRoundLabel(),
      entries: masked,
      total: masked.length,
    });

  } catch (err) {
    console.error('leaderboard error:', err);
    res.status(500).json({ error: 'Failed to fetch leaderboard.' });
  }
});

// ─── ROUTE 5: Get Round Stats ─────────────────────────────────────────────────
app.get('/api/stats', async (req, res) => {
  try {
    const round = getCurrentRound();
    const now = new Date();
    const lastDay = new Date(now.getFullYear(), now.getMonth() + 1, 0);
    const daysLeft = lastDay.getDate() - now.getDate();

    const { count } = await supabase
      .from('entries')
      .select('*', { count: 'exact', head: true })
      .eq('round', round)
      .eq('status', 'completed');

    res.json({
      round,
      round_label: getRoundLabel(),
      total_entries: count || 0,
      days_left: daysLeft,
      prize_value: '$120 AUD',
      entry_fee: '$10 AUD',
    });

  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch stats.' });
  }
});

// ─── HELPERS ─────────────────────────────────────────────────────────────────
function maskName(fullName) {
  if (!fullName) return 'Anonymous';
  const parts = fullName.trim().split(' ');
  if (parts.length === 1) return parts[0];
  return `${parts[0]} ${parts[parts.length - 1][0]}.`;
}

// ─── START ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`FootyQuiz backend running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});
