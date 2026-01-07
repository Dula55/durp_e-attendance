// setAdminClaim.js - Updated for Student Attendance System
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
    
    // Verify the user exists and get their info
    const user = await admin.auth().getUser(uid);
    
    console.log(`Successfully ${makeAdmin ? 'set' : 'revoked'} admin claim for UID: ${uid}`);
    console.log(`User Email: ${user.email || 'No email'}`);
    console.log(`User Display Name: ${user.displayName || 'No display name'}`);
    console.log(`Custom Claims: ${JSON.stringify(user.customClaims || {})}`);
    console.log('\nNote: The user\'s ID token must be refreshed (sign out/in or call getIdToken(true) on client) to pick up new claims.');
    
    process.exit(0);
  } catch (err) {
    console.error('Error setting custom claims:', err);
    process.exit(1);
  }
}

async function createAdminUser(email, password, displayName = 'Administrator') {
  try {
    // Create new user
    const user = await admin.auth().createUser({
      email,
      password,
      displayName,
      emailVerified: true
    });
    
    // Set admin claim
    await admin.auth().setCustomUserClaims(user.uid, { admin: true });
    
    console.log('\n✅ Admin user created successfully!');
    console.log(`UID: ${user.uid}`);
    console.log(`Email: ${user.email}`);
    console.log(`Display Name: ${user.displayName}`);
    console.log(`Custom Claims: { admin: true }`);
    console.log('\nUser can now log in with:');
    console.log(`Email: ${email}`);
    console.log(`Password: ${password}`);
    console.log('\nNote: The user must sign in to get the updated claims.');
    
    process.exit(0);
  } catch (err) {
    console.error('Error creating admin user:', err);
    process.exit(1);
  }
}

async function listUsers() {
  try {
    const listUsersResult = await admin.auth().listUsers(100);
    console.log('\n=== User List ===');
    listUsersResult.users.forEach((user) => {
      console.log(`\nUID: ${user.uid}`);
      console.log(`Email: ${user.email || 'No email'}`);
      console.log(`Display Name: ${user.displayName || 'No display name'}`);
      console.log(`Custom Claims: ${JSON.stringify(user.customClaims || {})}`);
      console.log(`Created: ${new Date(user.metadata.creationTime).toLocaleString()}`);
      console.log(`Last Sign In: ${user.metadata.lastSignInTime ? new Date(user.metadata.lastSignInTime).toLocaleString() : 'Never'}`);
    });
    process.exit(0);
  } catch (err) {
    console.error('Error listing users:', err);
    process.exit(1);
  }
}

// CLI args
const command = process.argv[2];

if (!command) {
  console.error(`
Usage:
  node setAdminClaim.js set <UID> [true|false]    - Set/revoke admin claim for existing user
  node setAdminClaim.js create <email> <password> [displayName] - Create new admin user
  node setAdminClaim.js list                       - List all users
  
Examples:
  node setAdminClaim.js set abc123 true            - Make user abc123 an admin
  node setAdminClaim.js set abc123 false           - Remove admin from user abc123
  node setAdminClaim.js create admin@example.com password123 "System Admin" - Create new admin
  node setAdminClaim.js list                      - List all users
  `);
  process.exit(1);
}

if (command === 'set') {
  const uid = process.argv[3];
  const makeAdmin = (process.argv[4] || 'true').toLowerCase() !== 'false';
  
  if (!uid) {
    console.error('Usage: node setAdminClaim.js set <UID> [true|false]');
    process.exit(1);
  }
  
  setAdmin(uid, makeAdmin);
} else if (command === 'create') {
  const email = process.argv[3];
  const password = process.argv[4];
  const displayName = process.argv[5] || 'Administrator';
  
  if (!email || !password) {
    console.error('Usage: node setAdminClaim.js create <email> <password> [displayName]');
    process.exit(1);
  }
  
  createAdminUser(email, password, displayName);
} else if (command === 'list') {
  listUsers();
} else {
  console.error(`Unknown command: ${command}`);
  console.error('Available commands: set, create, list');
  process.exit(1);
}