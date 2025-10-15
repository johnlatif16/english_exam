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

// API to track user attempts
app.post("/api/track-attempt", async (req, res) => {
  try {
    const { phone, action } = req.body; // action: 'start', 'refresh', 'submit', 'refresh_auto_submit'
    
    console.log(`Tracking attempt: ${phone} - ${action}`);
    
    await db.collection("attempts").add({
      phone,
      action,
      timestamp: new Date(),
      userAgent: req.get('User-Agent')
    });
    
    res.json({ message: "Attempt tracked successfully" });
  } catch (error) {
    console.error("Track attempt error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// API to get user attempts
app.get("/api/attempts/:phone", async (req, res) => {
  try {
    const { phone } = req.params;
    
    console.log(`Getting attempts for phone: ${phone}`);
    
    const snapshot = await db.collection("attempts")
      .where("phone", "==", phone)
      .orderBy("timestamp", "desc")
      .get();
    
    const attempts = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
      timestamp: doc.data().timestamp?.toDate?.() || doc.data().timestamp
    }));
    
    console.log(`Found ${attempts.length} attempts for ${phone}`);
    
    res.json(attempts);
  } catch (error) {
    console.error("Get attempts error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/submit", async (req, res) => {
  try {
    const { name, phone, correct, wrong, score, userAnswers } = req.body;
    
    console.log(`Submit request for: ${name}, ${phone}, Score: ${score}`);
    
    // Track submission attempt
    try {
      await db.collection("attempts").add({
        phone,
        action: 'submit',
        timestamp: new Date()
      });
    } catch (trackError) {
      console.error("Error tracking submission:", trackError);
    }
    
    // Check if user already submitted
    const existingSnapshot = await db.collection("results")
      .where("phone", "==", phone)
      .get();
    
    if (!existingSnapshot.empty) {
      const results = existingSnapshot.docs.map(doc => ({
        id: doc.id,
        ...doc.data()
      }));
      
      const latestResult = results.sort((a, b) => 
        new Date(b.timestamp) - new Date(a.timestamp)
      )[0];
      
      if (!latestResult.allowedRetake) {
        return res.status(400).json({ 
          message: "You have already submitted the quiz. Contact administrator to retake." 
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
      userAnswers,
      timestamp: new Date(),
      allowedRetake: false
    });
    
    res.json({ message: "Submitted successfully" });
  } catch (error) {
    console.error("Submit error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/results", verifyToken, async (req, res) => {
  try {
    const snapshot = await db.collection("results").orderBy("timestamp", "desc").get();
    const results = snapshot.docs.map((doc) => ({
      id: doc.id,
      ...doc.data(),
      timestamp: doc.data().timestamp?.toDate?.() || doc.data().timestamp
    }));
    res.json(results);
  } catch (error) {
    console.error("Results error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// Delete endpoint
app.delete("/api/results/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const doc = await db.collection("results").doc(id).get();
    if (!doc.exists) {
      return res.status(404).json({ message: "Result not found" });
    }
    
    await db.collection("results").doc(id).delete();
    
    res.json({ message: "Result deleted successfully" });
  } catch (error) {
    console.error("Delete error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// API to allow retaking quiz for a specific user
app.post("/api/results/:id/allow-retake", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const doc = await db.collection("results").doc(id).get();
    if (!doc.exists) {
      return res.status(404).json({ message: "Result not found" });
    }
    
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

// API to disallow retaking quiz for a specific user
app.post("/api/results/:id/disallow-retake", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const doc = await db.collection("results").doc(id).get();
    if (!doc.exists) {
      return res.status(404).json({ message: "Result not found" });
    }
    
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

// API to check if retake is allowed for a specific phone number
app.get("/api/check-retake/:phone", async (req, res) => {
  try {
    const { phone } = req.params;
    
    const snapshot = await db.collection("results")
      .where("phone", "==", phone)
      .get();
    
    if (snapshot.empty) {
      return res.json({ 
        allowedRetake: false,
        message: "No results found for this phone number" 
      });
    }
    
    const results = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
      timestamp: doc.data().timestamp?.toDate?.() || doc.data().timestamp
    }));
    
    const latestResult = results.sort((a, b) => 
      new Date(b.timestamp) - new Date(a.timestamp)
    )[0];
    
    res.json({ 
      allowedRetake: latestResult.allowedRetake || false,
      result: latestResult
    });
  } catch (error) {
    console.error("Check retake error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
