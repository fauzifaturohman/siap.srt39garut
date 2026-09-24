const { onCall, HttpsError } = require("firebase-functions/v2/https");
const admin = require("firebase-admin");
const bcrypt = require("bcryptjs");

admin.initializeApp();
const db = admin.firestore();
const auth = admin.auth();

/**
 * Cloud Function: loginWithNISNIP
 * Input : { identifier: "12345" | "1987654321", password: "xxxx", role: "siswa" | "guru" }
 * Output: { customToken: "..." , role: "..." }
 */
exports.loginWithNISNIP = onCall({ region: "asia-southeast2" }, async (request) => {
  const { identifier, password, role } = request.data;

  if (!identifier || !password || !role) {
    throw new HttpsError("invalid-argument", "NIS/NIP, password, dan role wajib diisi.");
  }

  // Pilih koleksi berdasarkan role
  const collection = role === "siswa" ? "students" : "staff";
  const field = role === "siswa" ? "nis" : "nip";

  // Cari user berdasarkan NIS/NIP
  const snap = await db.collection(collection).where(field, "==", identifier).limit(1).get();
  if (snap.empty) {
    throw new HttpsError("not-found", "NIS/NIP tidak terdaftar.");
  }

  const userDoc = snap.docs[0];
  const userData = userDoc.data();

  // Verifikasi password (hash bcrypt)
  const ok = await bcrypt.compare(password, userData.passwordHash || "");
  if (!ok) {
    throw new HttpsError("unauthenticated", "Password salah.");
  }

  if (userData.active === false) {
    throw new HttpsError("permission-denied", "Akun tidak aktif. Hubungi Satgas SR.");
  }

  // Tentukan UID Firebase (buat jika belum ada)
  const uid = userData.uid || `${role}_${identifier}`;

  // Buat / update user di Firebase Auth
  try {
    await auth.getUser(uid);
  } catch {
    await auth.createUser({ uid, displayName: userData.nama });
  }

  // Set Custom Claims (role-based access)
  const claims = {
    role: role,                    // "siswa" | "guru" | "satgas" | "kepsek" | "pusat"
    nis: userData.nis || null,
    nip: userData.nip || null,
    kelas: userData.kelas || null,
    nama: userData.nama || null
  };
  await auth.setCustomUserClaims(uid, claims);

  // Update lastLogin
  await userDoc.ref.update({ lastLogin: admin.firestore.FieldValue.serverTimestamp() });

  // Buat custom token
  const customToken = await auth.createCustomToken(uid, claims);

  return { customToken, role, nama: userData.nama };
});

/**
 * Cloud Function: seedUser
 * Digunakan admin untuk membuat akun siswa/guru baru.
 * Hanya bisa dipanggil oleh user dengan claim role = "pusat" atau "kepsek".
 */
exports.seedUser = onCall({ region: "asia-southeast2" }, async (request) => {
  if (!request.auth) throw new HttpsError("unauthenticated", "Harus login.");
  const claims = request.auth.token;
  if (!["pusat", "kepsek", "satgas"].includes(claims.role)) {
    throw new HttpsError("permission-denied", "Tidak berwenang.");
  }

  const { nama, nis, nip, password, role, kelas } = request.data;
  if (!nama || !password || !role) {
    throw new HttpsError("invalid-argument", "Data tidak lengkap.");
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const collection = role === "siswa" ? "students" : "staff";
  const doc = {
    nama, passwordHash, role, kelas: kelas || null,
    nis: nis || null, nip: nip || null,
    active: true,
    createdAt: admin.firestore.FieldValue.serverTimestamp()
  };

  if (nis) {
    const dup = await db.collection("students").where("nis","==",nis).get();
    if (!dup.empty) throw new HttpsError("already-exists", "NIS sudah terdaftar.");
  }
  if (nip) {
    const dup = await db.collection("staff").where("nip","==",nip).get();
    if (!dup.empty) throw new HttpsError("already-exists", "NIP sudah terdaftar.");
  }

  const ref = await db.collection(collection).add(doc);
  return { id: ref.id, message: "Akun berhasil dibuat." };
});
