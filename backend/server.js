const express = require("express");
const mysql = require("mysql");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const cors = require("cors");
const path = require("path");

dotenv.config();
const SECRET_KEY = process.env.SECRET_KEY;

const app = express();
app.use(express.json());
app.use(cors());

// ✅ Serve the frontend folder as static
app.use(express.static(path.join(__dirname, "../frontend")));

// ✅ Database connection
const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "majorproject"
});

db.connect(err => {
    if (err) console.error("Database connection failed:", err);
    else console.log("Connected to MySQL database");
});

// ✅ Serve signup page correctly
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "../frontend/signup.html"));
});

// ✅ JWT Middleware
const verifyToken = (req, res, next) => {
    const token = req.header("Authorization");
    if (!token) return res.status(403).send("Access Denied");
    try {
        const verified = jwt.verify(token.replace("Bearer ", ""), SECRET_KEY);
        req.user = verified;
        next();
    } catch (err) {
        res.status(401).send("Invalid Token");
    }
};

// ✅ Signup Route (Fixed SQL query & error handling)
app.post("/signup", async (req, res) => {
    const { name, email, password, role } = req.body;
    try {
        const checkUserQuery = "SELECT * FROM signup WHERE email = ?";
        db.query(checkUserQuery, [email], async (err, result) => {
            if (err) {
                console.error(err);
                return res.status(500).send("Database error");
            }
            if (result.length > 0) return res.status(400).send("User already exists");

            const hashedPassword = await bcrypt.hash(password, 10);
            const insertQuery = "INSERT INTO signup (username, email, password, role) VALUES (?, ?, ?, ?)";
            db.query(insertQuery, [name, email, hashedPassword, role], (err, result) => {
                if (err) {
                    console.error(err);
                    return res.status(500).send("Error registering user");
                }

                const token = jwt.sign({ email, role }, SECRET_KEY, { expiresIn: "1h" });
                res.status(201).json({ message: "User registered successfully", token });
                // res.redirect('/signin')
            });
        });
    } catch (error) {
        console.error(error);
        res.status(500).send("Internal server error");
    }
});

// ✅ Signin Route (Fixed response structure)
app.post("/signin", (req, res) => {
    const { email, password } = req.body;
    const sql = "SELECT * FROM signup WHERE email = ?";
    db.query(sql, [email], async (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).send("Database error");
        }
        if (result.length === 0) return res.status(401).send("Invalid email or password");

        const user = result[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).send("Invalid credentials");

        const token = jwt.sign({ user_id: user.user_id, email: user.email, role: user.role }, SECRET_KEY, { expiresIn: "1h" });
        res.json({ message: "Login successful", token, role: user.role });
    });
});

// ✅ Protected Route (Fixed file path)
app.get('/home', verifyToken, (req, res) => {
    res.sendFile(path.join(__dirname, "../frontend/home.html"));
});

// ✅ Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
