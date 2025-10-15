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
  try {
    const { name, phone, correct, wrong, score, userAnswers } = req.body;
    
    // Check if user already submitted
    const existingSnapshot = await db.collection("results")
      .where("phone", "==", phone)
      .get();
    
    if (!existingSnapshot.empty) {
      // Check if retake is allowed
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
      
      // If retake is allowed, delete old results for this phone
      const deletePromises = existingSnapshot.docs.map(doc => doc.ref.delete());
      await Promise.all(deletePromises);
    }
    
    await db.collection("results").add({ 
      name, 
      phone, 
      correct, 
      wrong, 
      score, 
      userAnswers, // أضف هذا الحقل
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
      ...doc.data()
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
    
    // Verify the result exists
    const doc = await db.collection("results").doc(id).get();
    if (!doc.exists) {
      return res.status(404).json({ message: "Result not found" });
    }
    
    // Delete the result
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
    
    // Verify the result exists
    const doc = await db.collection("results").doc(id).get();
    if (!doc.exists) {
      return res.status(404).json({ message: "Result not found" });
    }
    
    // Update the result to mark it as allowed for retake
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
    
    // Verify the result exists
    const doc = await db.collection("results").doc(id).get();
    if (!doc.exists) {
      return res.status(404).json({ message: "Result not found" });
    }
    
    // Update the result to mark it as not allowed for retake
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
    
    // Find results by phone number
    const snapshot = await db.collection("results")
      .where("phone", "==", phone)
      .get();
    
    if (snapshot.empty) {
      return res.json({ 
        allowedRetake: false,
        message: "No results found for this phone number" 
      });
    }
    
    // Get the most recent result
    const results = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
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
