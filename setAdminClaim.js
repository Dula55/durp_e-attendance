// setAdminClaim.js
const admin = require('firebase-admin');
const fs = require('fs');

// Path to service account JSON you download from Firebase console
const serviceAccountPath = './serviceAccountKey.json';

if (!fs.existsSync(serviceAccountPath)) {
  console.error('Missing serviceAccountKey.json. Obtain it from Firebase Console -> Project Settings -> Service accounts.');
  process.exit(1);
}

const serviceAccount = require(serviceAccountPath);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  // optional but recommended: provide your DB URL
  // databaseURL: "https://<PROJECT-ID>.firebaseio.com"
});

async function setAdmin(uid, makeAdmin = true) {
  try {
    const claims = makeAdmin ? { admin: true } : null; // passing null removes custom claims
    await admin.auth().setCustomUserClaims(uid, claims);
    console.log(`Successfully ${makeAdmin ? 'set' : 'revoked'} admin claim for UID: ${uid}`);
    console.log('Note: the user's ID token must be refreshed (sign out/in or call getIdToken(true) on client) to pick up new claims.');
    process.exit(0);
  } catch (err) {
    console.error('Error setting custom claims:', err);
    process.exit(1);
  }
}

// CLI args
const uid = process.argv[2];
const makeAdmin = (process.argv[3] || 'true').toLowerCase() !== 'false';

if (!uid) {
  console.error('Usage: node setAdminClaim.js <UID> [true|false]');
  process.exit(1);
}

setAdmin(uid, makeAdmin);
