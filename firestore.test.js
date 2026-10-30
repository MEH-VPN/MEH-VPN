const {
  initializeTestEnvironment,
  assertFails,
  assertSucceeds,
} = require("@firebase/rules-unit-testing");
const { test, before, after, beforeEach } = require("node:test");
const fs = require("node:fs");

let testEnv;
const PROJECT_ID = process.env.GCP_PROJECT || "demo-no-project";
const ALICE_UID = "alice_123";
const BOB_UID = "bob_456";

const [emulatorHost, emulatorPortStr] = (
  process.env.FIRESTORE_EMULATOR_HOST || "127.0.0.1:8085"
).split(":");
const emulatorPort = parseInt(emulatorPortStr, 10);

before(async () => {
  const rules = fs.readFileSync("./firestore.rules", "utf8");
  testEnv = await initializeTestEnvironment({
    projectId: PROJECT_ID,
    firestore: {
      rules,
      host: emulatorHost,
      port: emulatorPort,
    },
  });
});

after(async () => {
  if (testEnv) {
    await testEnv.cleanup();
  }
});

beforeEach(async () => {
  if (testEnv) {
    await testEnv.clearFirestore();
  }
});

function validPayload(userId, now = new Date()) {
  return {
    userId,
    countryNameFa: "آلمان",
    flagEmoji: "🇩🇪",
    rawUri: "vless://11111111-2222-3333-4444-555555555555@de.meh.example.com:443?security=tls#DE",
    sourceRepo: "SoliSpirit/v2ray-configs",
    pingMs: 85,
    createdAt: now,
  };
}

test("Unauthenticated user: cannot read connection_logs", async () => {
  const unauthDb = testEnv.unauthenticatedContext().firestore();
  await assertFails(
    unauthDb.collection("users").doc(ALICE_UID).collection("connection_logs").get()
  );
});

test("Unauthenticated user: cannot create connection_log", async () => {
  const unauthDb = testEnv.unauthenticatedContext().firestore();
  await assertFails(
    unauthDb
      .collection("users")
      .doc(ALICE_UID)
      .collection("connection_logs")
      .doc("log_1")
      .set(validPayload(ALICE_UID))
  );
});

test("Authenticated user: can create and read their own connection_log", async () => {
  const aliceDb = testEnv.authenticatedContext(ALICE_UID).firestore();
  const docRef = aliceDb
    .collection("users")
    .doc(ALICE_UID)
    .collection("connection_logs")
    .doc("log_1");

  await assertSucceeds(docRef.set(validPayload(ALICE_UID)));
  await assertSucceeds(docRef.get());
  await assertSucceeds(
    aliceDb.collection("users").doc(ALICE_UID).collection("connection_logs").get()
  );
});

test("Authenticated user: cannot read another user's connection_log", async () => {
  await testEnv.withSecurityRulesDisabled(async (context) => {
    await context
      .firestore()
      .collection("users")
      .doc(BOB_UID)
      .collection("connection_logs")
      .doc("bob_log")
      .set(validPayload(BOB_UID));
  });

  const aliceDb = testEnv.authenticatedContext(ALICE_UID).firestore();
  await assertFails(
    aliceDb
      .collection("users")
      .doc(BOB_UID)
      .collection("connection_logs")
      .doc("bob_log")
      .get()
  );
  await assertFails(
    aliceDb.collection("users").doc(BOB_UID).collection("connection_logs").get()
  );
});

test("Authenticated user: rejects spoofed userId or shadow fields", async () => {
  const aliceDb = testEnv.authenticatedContext(ALICE_UID).firestore();
  const docRef = aliceDb
    .collection("users")
    .doc(ALICE_UID)
    .collection("connection_logs")
    .doc("log_spoof");

  await assertFails(docRef.set({ ...validPayload(BOB_UID) }));
  await assertFails(docRef.set({ ...validPayload(ALICE_UID), isAdmin: true }));
});

test("Authenticated user: can update allowed fields but cannot mutate createdAt or userId", async () => {
  const createdTime = new Date(Date.now() - 5000);
  await testEnv.withSecurityRulesDisabled(async (context) => {
    await context
      .firestore()
      .collection("users")
      .doc(ALICE_UID)
      .collection("connection_logs")
      .doc("log_upd")
      .set(validPayload(ALICE_UID, createdTime));
  });

  const aliceDb = testEnv.authenticatedContext(ALICE_UID).firestore();
  const docRef = aliceDb
    .collection("users")
    .doc(ALICE_UID)
    .collection("connection_logs")
    .doc("log_upd");

  await assertSucceeds(docRef.update({ pingMs: 64, updatedAt: new Date() }));
  await assertFails(docRef.update({ userId: BOB_UID }));
  await assertFails(docRef.update({ createdAt: new Date() }));
});
