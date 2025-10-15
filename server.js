import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import helmet from "helmet";
import bcrypt from "bcryptjs";
import { initializeApp, cert } from "firebase-admin/app";
import { getFirestore } from "firebase-admin/firestore";

dotenv.config();

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static("public"));
app.use(helmet()); // ✅ حماية HTTP Headers

// --- Firebase Init ---
const FIREBASE_CONFIG = JSON.parse(process.env.FIREBASE_CONFIG);
initializeApp({ credential: cert(FIREBASE_CONFIG) });
const db = getFirestore();

// --- Middleware للتحقق من JWT ---
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ message: "No token provided" });

  const token = authHeader.split(" ")[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(401).json({ message: "Invalid or expired token" });
    req.user = user;
    next();
  });
}

// --- تسجيل الدخول ---
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  if (username !== process.env.ADMIN_USERNAME) {
    return res.status(401).json({ message: "Invalid username" });
  }

  try {
    const match = await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH);
    if (!match) {
      return res.status(401).json({ message: "Invalid password" });
    }

    const token = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: "2h" });
    res.json({ token });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Server error during login" });
  }
});

// --- تحقق من صلاحية التوكن ---
app.get("/api/verify-token", verifyToken, (req, res) => {
  res.json({ valid: true, user: req.user });
});

// --- حفظ نتائج الاختبار ---
app.post("/api/submit", async (req, res) => {
  try {
    const { name, phone, correct, wrong, score } = req.body;

    const existingSnapshot = await db.collection("results").where("phone", "==", phone).get();

    if (!existingSnapshot.empty) {
      const results = existingSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
      const latest = results.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))[0];

      if (!latest.allowedRetake) {
        return res.status(400).json({
          message: "You have already submitted the quiz. Contact admin to retake."
        });
      }

      const deletePromises = existingSnapshot.docs.map(doc => doc.ref.delete());
      await Promise.all(deletePromises);
    }

    await db.collection("results").add({
      name,
      phone,
      correct,
      wrong,
      score,
      timestamp: new Date(),
      allowedRetake: false
    });

    res.json({ message: "Submitted successfully" });
  } catch (error) {
    console.error("Submit error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// --- عرض النتائج ---
app.get("/api/results", verifyToken, async (req, res) => {
  try {
    const snapshot = await db.collection("results").orderBy("timestamp", "desc").get();
    const results = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    res.json(results);
  } catch (error) {
    console.error("Results error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// --- حذف نتيجة ---
app.delete("/api/results/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const doc = await db.collection("results").doc(id).get();
    if (!doc.exists) return res.status(404).json({ message: "Result not found" });

    await db.collection("results").doc(id).delete();
    res.json({ message: "Result deleted successfully" });
  } catch (error) {
    console.error("Delete error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// --- السماح بإعادة الاختبار ---
app.post("/api/results/:id/allow-retake", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const doc = await db.collection("results").doc(id).get();
    if (!doc.exists) return res.status(404).json({ message: "Result not found" });

    await db.collection("results").doc(id).update({
      allowedRetake: true,
      retakeAllowedAt: new Date()
    });
    res.json({ message: "Quiz retake allowed successfully" });
  } catch (error) {
    console.error("Allow retake error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// --- منع إعادة الاختبار ---
app.post("/api/results/:id/disallow-retake", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const doc = await db.collection("results").doc(id).get();
    if (!doc.exists) return res.status(404).json({ message: "Result not found" });

    await db.collection("results").doc(id).update({
      allowedRetake: false,
      retakeDisallowedAt: new Date()
    });
    res.json({ message: "Quiz retake disallowed successfully" });
  } catch (error) {
    console.error("Disallow retake error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// --- التحقق من السماح بالإعادة برقم الهاتف ---
app.get("/api/check-retake/:phone", async (req, res) => {
  try {
    const { phone } = req.params;
    const snapshot = await db.collection("results").where("phone", "==", phone).get();

    if (snapshot.empty) {
      return res.json({ allowedRetake: false, message: "No results found for this number" });
    }

    const results = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    const latest = results.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))[0];

    res.json({ allowedRetake: latest.allowedRetake || false, result: latest });
  } catch (error) {
    console.error("Check retake error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on http://localhost:${PORT}`));
