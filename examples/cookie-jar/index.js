/* COMMON VULNERABILITIES OF COOKIES

1.) SESSION HIJACKING
  exploits active sessions (cookie value) to gain unauthorized access- the attacker can 
  become the user as far as the server is concerned

2.) CROSS-SITE SCRIPTING (XSS)
  malicious script injected via input fields or URLs- the script then accesses cookies
  and sends them to an attacker

3.) CROSS-SITE REQUEST FORGERY (CSRF)
  a user is tricked into executing actions via a forged request exploiting that user's
  authenticated session

*/

import { createServer, startServer } from '#shared';
import { readFile } from 'fs/promises';
//!!! = my additions
// takes request header from request object and parses-out key-value pairs
import cookieParser from 'cookie-parser'; //!!!
/* crypto module is a built-in Node.js module that provides cryptographic 
functionality, including the generation of secure random values */
import crypto from 'crypto'; //!!!

import db from './database.js';

const cookieSecret = 'super-secret'; //!!!

const app = createServer({ cookies: false });

/* 
-passing an argument (secret) to cookieParser() is in practice the addition of a 
  generated 'signature' (a cryptographic hash) to the cookie
  1.) the signature is a hash of the cookie's value + the secret passed to cookieParser
  2.) if the client modifies the value of a signed cookie, the appended signature will 
      no longer match when the server verifies it, and the change will be detected

-when the server receives a signed cookie, cookie-parser verifies the signature using 
  the provided secret. if the signature is invalid (e.g., the cookie has been tampered 
  with), the signed cookie is ignored

-a cookie’s value is still visible to the client. Signing ensures integrity (not 
  secrecy). for confidentiality, use encryption
*/
app.use(cookieParser(cookieSecret)); //!!!

/* 
-'crypto.randomBytes(16)' generates a buffer (binary data) containing 16 random bytes 
  (128 bits) using a secure pseudo-random number generator

-'.toString('hex')' converts the buffer of 16 random bytes into a string in hexadecimal 
  format

-Will produce a new, random 32-character string i.e. 'c4e8d729af03f14d9c5a7d6e7b6f382a'

- session ID is highly unlikely to collide with another because it’s generated using 
  secure random values, plus 32-character hexadecimal string provides a sufficiently 
  large key space for secure session identification (16^32 possible combinations)
*/
const generateSessionId = () => {
  return crypto.randomBytes(16).toString('hex');
}; //!!!

app.get('/', (req, res) => {
  if (!req.cookies) res.send('Cookies are disabled.');
  // below changed from 'req.cookies.username' to ==> 'req.signedCookies.username'
  if (req.signedCookies.username) {
    //!!!
    res.redirect('/profile');
  } else {
    res.redirect('/login');
  }
});

app.get('/login', async (req, res) => {
  const loginPage = await readFile('./pages/login.html', 'utf-8');

  if (req.cookies.username) {
    res.redirect('/profile');
  }

  if (req.query.error) {
    res
      .status(403)
      .send(loginPage.replace('{{error}}', String(req.query.error)));
    return;
  }

  res.send(loginPage);
});

// Simulate user login and set a cookie
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const user = await db.get(
    'SELECT * FROM users WHERE username = ? AND password = ?',
    [username, password]
  );

  //!!!
  if (user) {
    const sessionId = generateSessionId();
    await db.run('INSERT INTO sessions (id, username) VALUES (?, ?)', [
      sessionId,
      username,
    ]);
    res.cookie('sessionId', sessionId, {
      /* 
      -when a cookie is marked as 'httpOnly' the cookie;
        1.) cannot be accessed via client-side scripts (this includes JS running 
        in the browser). WITHOUT the 'httpOnly' flag, can be read or modified 
        using 'document.cookie' in JavaScript
        2.) can only be sent in HTTP requests

      -protects against Cross-Site Scripting (XSS); injecting malicious (JS) scripts
        into a web page

      -does not protect against Cross-Site Request Forgery (CSRF) (an attacker uses a 
        logged-in user's session to perform unauthorized actions)

      -since the cookie is inaccessible to JavaScript, client-side logic (like 
        conditionally showing UI elements based on a cookie value) won't work.
      */
      httpOnly: true,
      /* 
      -when a cookie is marked as 'secure':
        1.) The browser will only include the cookie in requests made to the server 
        if the connection is encrypted using HTTPS. if the connection is HTTP 
        (unencrypted), the cookie is not sent
        2.)  It protects the cookie from being intercepted by attackers during 
        transit (e.g., through man-in-the-middle attacks on an unencrypted network).

      -any cookies containing personally identifiable information (PII) or critical 
        application data should be marked as secure.

      -the secure flag ensures the cookie is encrypted during transmission but does 
        not protect it if the application or browser is compromised.

      -During development, most local servers (e.g., http://localhost) do not use HTTPS. 
        if the secure flag is enabled, cookies marked as secure would not be sent by 
        the browser because the connection is not encrypted (hence the code below). the 
        secure cookie option is only enabled in production environments and not during 
        development
      */
      secure: process.env.NODE_ENV === 'production',
      /*
      -when '{ signed: true }' is passed to res.cookie, Express uses a secret (set via 
        cookieParser(secret)) to create a signature for the cookie value

      -use 'signed: true' for sensitive cookies like session identifiers, but ensure the 
        cookieParser secret is securely managed
      */
      signed: true,
    });
    res.redirect('/profile');
  }
  //!!!
  else {
    res.status(403).redirect('/login?error=Invalid login credentials.');
  }
});

app.post('/logout', (_, res) => {
  res.clearCookie('username');
  res.redirect('/login');
});

// Display user profile only if the username cookie exists
app.get('/profile', async (req, res) => {
  res.locals.title = 'Profile';

  const sessionId = req.signedCookies.sessionId; //!!!

  if (!sessionId) {
    return res.redirect('/login?error=Please login to view your profile.');
  }

  const session = await db.get(
    'SELECT * FROM sessions WHERE id = ?',
    sessionId
  ); //!!!
  const user = await db.get(
    'SELECT * FROM users WHERE username = ?',
    session.username
  ); //!!!

  if (user && user.username) {
    res.send(
      (await readFile('./pages/profile.html', 'utf-8')).replace(
        '{{username}}',
        user.username
      )
    );
  } else {
    return res.redirect('/login?error=Please login to view your profile.');
  }
});

startServer(app, { name: 'Cookie Jar' });
