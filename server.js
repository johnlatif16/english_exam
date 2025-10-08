import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { initializeApp, cert } from "firebase-admin/app";
import { getFirestore } from "firebase-admin/firestore";

dotenv.config();

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static("public"));

const FIREBASE_CONFIG = JSON.parse(process.env.FIREBASE_CONFIG);
initializeApp({ credential: cert(FIREBASE_CONFIG) });
const db = getFirestore();

// --- Authentication middleware ---
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ message: "No token" });
  const token = authHeader.split(" ")[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(401).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
}

// --- API routes ---
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  if (
    username === process.env.ADMIN_USERNAME &&
    password === process.env.ADMIN_PASSWORD
  ) {
    const token = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: "2h" });
    res.json({ token });
  } else {
    res.status(401).json({ message: "Invalid credentials" });
  }
});

app.post("/api/submit", async (req, res) => {
  const { name, phone, correct, wrong, score } = req.body;
  await db.collection("results").add({ name, phone, correct, wrong, score, timestamp: new Date() });
  res.json({ message: "Submitted" });
});

app.get("/api/results", verifyToken, async (req, res) => {
  const snapshot = await db.collection("results").orderBy("timestamp", "desc").get();
  const results = snapshot.docs.map((doc) => doc.data());
  res.json(results);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
