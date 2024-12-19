//!!! = my additions

import crypto from 'crypto';

/* 
-Version 4 (UUIDv4): Randomly generated UUIDs (Universally Unique IDentifiers), 
 typically the most common use case
 
-Probability of collision is near-zero; UUIDv4 has 2^122 possible values due to 
its 128-bit length and the fact that some bits are reserved for version and variant 
information

*/
import { v4 as uuid } from 'uuid'; //!!!

import { startServer, createServer } from '#shared';
import { db } from './database.js';
import { currentUser } from './middleware.js';

const app = createServer();

app.use(currentUser);

app.get('/', (req, res) => {
  if (res.locals.user) return res.redirect('/account');
  res.redirect('/login');
});

app.get('/account', async (req, res) => {
  const user = res.locals.user;
  const message = req.query.message;

  if (!user) {
    return res.redirect('/login?error=Please log in first.');
  }

  // pull token (generated after login) from database
  const { token } = await db.get(
    'SELECT token FROM sessions WHERE userId = ?',
    user.id
  ); //!!!

  const friends = await db.all(
    'SELECT id, username FROM users WHERE id != ?',
    user.id
  );

  // token is rendered on <input /> with type='hidden'
  res.render('account', { title: 'Sea Surf Bank', friends, message, token });
});

app.get('/login', (req, res) => {
  if (res.locals.user) return res.redirect('/account');
  const error = req.query.error;
  res.render('login', { title: 'Login', error });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const user = await db.get(
    'SELECT * FROM users WHERE username = ? AND password = ?',
    [username, password]
  );

  if (!user) {
    return res.redirect('/login?error=Invalid username or password');
  }

  const sessionId = crypto.randomBytes(16).toString('hex');
  // generate a random, 128-bit (32-character) string (i.e. '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d')
  const token = uuid(); //!!!
  // write the token to the database
  try {
    await db.run(
      `INSERT INTO sessions (sessionId, userId, token) VALUES (?, ?, ?)`,
      [
        sessionId,
        user.id,
        token, //!!!
      ]
    );

    res.cookie('sessionId', sessionId);
    res.redirect('/account');
  } catch (error) {
    console.error(error);
    return res.redirect(
      '/login?error=Error creating session. Please try again.'
    );
  }
});

app.get('/transfer', (_, res) => {
  res.render('transfer', { title: 'Transfer' });
});

app.post('/transfer', async (req, res) => {
  const { user } = res.locals;
  const { amount, recipient } = req.body;

  // pull token (generated after login) from database
  const { token } = await db.get(
    'SELECT token FROM sessions WHERE userId = ?',
    user.id
  ); //!!!

  // check token against hidden <input /> form. If token is not the same (absent) send 403
  if (token !== req.body._csrf) {
    return res.status(403).send('Unauthorized'); //!!!
  }

  try {
    await db.run('UPDATE users SET balance = balance - ? WHERE id = ?', [
      amount,
      user.id,
    ]);

    await db.run('UPDATE users SET balance = balance + ? WHERE id = ?', [
      amount,
      recipient,
    ]);

    if (req.headers['referer']?.includes('/account')) {
      return res.redirect(`/account?message=Transfer successful!`);
    }

    console.log(`Transferred $${amount} from ${user.username}.`);
    res.sendStatus(202);
  } catch (err) {
    return res.status(500).send('Error updating balance');
  }
});

app.post('/logout', async (req, res) => {
  const sessionId = req.cookies.sessionId;

  if (!sessionId) {
    return res.redirect('/login');
  }

  await db.run('DELETE FROM sessions WHERE sessionId = ?', sessionId);

  res.clearCookie('sessionId');
  res.redirect('/login');
});

app.get('/evil', async (req, res) => {
  res.render('malicious', { title: 'Malicious', port: process.env.PORT });
});

startServer(app, { name: 'Sea Surf' });
