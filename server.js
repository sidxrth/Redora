require("dotenv").config();
const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const sqlite3 = require("sqlite3").verbose();
const SQLiteStore = require("connect-sqlite3")(session);
const cron = require("node-cron");
const cors = require("cors");
const axios = require("axios");
const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3");
const { v4: uuidv4 } = require("uuid");

const app = express();
const port = 3000;

// AWS S3 Configuration
const AWS_ACCESS_KEY_ID = process.env.AWS_ACCESS_KEY_ID;
const AWS_SECRET_ACCESS_KEY = process.env.AWS_SECRET_ACCESS_KEY;
const AWS_REGION = process.env.AWS_REGION || "ap-south-1";
const S3_BUCKET_NAME = process.env.S3_BUCKET_NAME;

const s3Client = new S3Client({
    region: AWS_REGION,
    credentials: {
        accessKeyId: AWS_ACCESS_KEY_ID,
        secretAccessKey: AWS_SECRET_ACCESS_KEY,
    },
});

// Middleware
app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// Session setup
app.use(
    session({
        secret: "a_very_strong_and_random_secret_key_for_sessions",
        resave: false,
        saveUninitialized: false,
        store: new SQLiteStore({
            db: "sessions.db",
            table: "sessions",
            dir: "./",
        }),
        cookie: {
            secure: false,
            httpOnly: true,
            maxAge: 1000 * 60 * 60 * 24, // 24 hours
        },
    }),
);

// Database setup for users
const DB_PATH = "./users.db";
const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) return console.error("Error connecting to users.db:", err.message);
    console.log("Connected to users.db");
    db.run(
        `
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fullName TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            dateOfJoin TEXT DEFAULT CURRENT_TIMESTAMP,
            profileImageURL TEXT DEFAULT NULL
        )
    `,
        (err) => {
            if (err) console.error("Error creating users table:", err.message);
            else console.log("Users table ready.");
        },
    );
});

// --- Google Gemini API Setup ---
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_URL = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${GEMINI_API_KEY}`;

let currentStoryPrompt = {
    month: "",
    prompt: "",
    dateGenerated: "",
};

// Function to generate story prompt using Google Gemini
async function generateStoryPrompt() {
    const date = new Date();
    const currentMonth = date.toLocaleString("default", {
        month: "long",
        year: "numeric",
    });

    // Check if prompt for current month exists in DB
    taskDB.get(
        `SELECT * FROM prompts WHERE month = ?`,
        [currentMonth],
        async (err, row) => {
            if (err) {
                console.error("❌ DB check error for prompt:", err.message);
                return;
            }

            if (row) {
                currentStoryPrompt = {
                    month: row.month,
                    prompt: row.prompt,
                    dateGenerated: row.dateGenerated,
                };
                console.log(
                    "✅ Loaded existing prompt from DB:",
                    currentStoryPrompt,
                );
            } else {
                // Generate new prompt if not found
                if (!GEMINI_API_KEY) {
                    console.error(
                        "❌ Gemini API Key is not set. Cannot generate new prompt.",
                    );
                    currentStoryPrompt = {
                        month: currentMonth,
                        prompt: "Write a story about a hidden portal found in an old library...", // Fallback
                        dateGenerated: new Date().toISOString(),
                    };
                    return;
                }

                try {
                    console.log("Attempting to generate a new story prompt via Gemini...");
                    const response = await axios.post(GEMINI_URL, {
                        contents: [{
                            parts: [{
                                text: "Write only the first 2–3 lines of a short, imaginative story for teenagers. Keep it engaging and under 50 words."
                            }]
                        }]
                    });

                    // Extract text from Gemini response structure
                    const prompt = response.data.candidates[0].content.parts[0].text.trim();
                    const dateGenerated = date.toISOString();
                    
                    currentStoryPrompt = {
                        month: currentMonth,
                        prompt,
                        dateGenerated,
                    };

                    // Save new prompt to DB
                    taskDB.run(
                        `
                    INSERT INTO prompts (month, prompt, dateGenerated)
                    VALUES (?, ?, ?)
                `,
                        [currentMonth, prompt, dateGenerated],
                        (insertErr) => {
                            if (insertErr)
                                console.error(
                                    "❌ Insert error:",
                                    insertErr.message,
                                );
                            else console.log("✅ New prompt saved to DB.");
                        },
                    );
                } catch (apiErr) {
                    console.error(
                        "❌ API error during prompt generation:",
                        apiErr.response?.data || apiErr.message,
                    );
                    currentStoryPrompt = {
                        month: currentMonth,
                        prompt: "The old clock tower hadn't chimed in a century, until the night the green fog rolled in...", // Fallback
                        dateGenerated: new Date().toISOString(),
                    };
                    console.warn("Using fallback prompt due to API error.");
                }
            }
        },
    );
}

// Database setup for tasks, prompts, and stories
const TASK_DB_PATH = path.join(__dirname, "task.db");
const taskDB = new sqlite3.Database(TASK_DB_PATH, (err) => {
    if (err) return console.error("Error connecting to task.db:", err.message);
    console.log("Connected to task.db");

    // Attach users.db to this taskDB connection
    taskDB.run(`ATTACH DATABASE '${DB_PATH}' AS users_db`, (attachErr) => {
        if (attachErr) {
            console.error(
                "Error attaching users.db to task.db:",
                attachErr.message,
            );
        } else {
            console.log("users.db attached to task.db connection.");
        }
    });

    // Create prompts table
    taskDB.run(
        `
        CREATE TABLE IF NOT EXISTS prompts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            month TEXT,
            prompt TEXT,
            dateGenerated TEXT
        )
    `,
        (err) => {
            if (err) {
                console.error("Error creating prompts table:", err.message);
            } else {
                console.log("Prompts table ready.");
                generateStoryPrompt(); // Generate/load prompt on startup
            }
        },
    );

    // Create published_stories table
    taskDB.run(
        `
        CREATE TABLE IF NOT EXISTS published_stories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            userId INTEGER NOT NULL,
            storyTitle TEXT NOT NULL,
            fullStoryContent TEXT NOT NULL,
            image TEXT DEFAULT 'https://placehold.co/300x200/556B2F/FFFFFF?text=Story',
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'draft' NOT NULL,
            FOREIGN KEY (userId) REFERENCES users(id)
        )
    `,
        (err) => {
            if (err)
                console.error(
                    "Error creating published_stories table:",
                    err.message,
                );
            else console.log("Published stories table ready.");
        },
    );

    // Create follows table
    taskDB.run(
        `
        CREATE TABLE IF NOT EXISTS follows (
            followerId INTEGER NOT NULL,
            followingId INTEGER NOT NULL,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (followerId, followingId),
            FOREIGN KEY (followerId) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (followingId) REFERENCES users(id) ON DELETE CASCADE
        )
    `,
        (err) => {
            if (err)
                console.error("Error creating follows table:", err.message);
            else console.log("Follows table ready.");
        },
    );

    // Create likes table
    taskDB.run(
        `
        CREATE TABLE IF NOT EXISTS likes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            storyId INTEGER NOT NULL,
            userId INTEGER NOT NULL,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (storyId, userId),
            FOREIGN KEY (storyId) REFERENCES published_stories(id) ON DELETE CASCADE,
            FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
        )
    `,
        (err) => {
            if (err) console.error("Error creating likes table:", err.message);
            else console.log("Likes table ready.");
        },
    );

    // Create comments table
    taskDB.run(
        `
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            storyId INTEGER NOT NULL,
            userId INTEGER NOT NULL,
            commentText TEXT NOT NULL,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (storyId) REFERENCES published_stories(id) ON DELETE CASCADE,
            FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
        )
    `,
        (err) => {
            if (err)
                console.error("Error creating comments table:", err.message);
            else console.log("Comments table ready.");
        },
    );
});

// Authentication Middleware
function isAuthenticated(req, res, next) {
    if (req.session.isLoggedIn && req.session.userId) {
        next();
    } else {
        res.redirect("/pages/login.html");
    }
}

// --- API Endpoints ---

// User Registration
app.post("/api/register", async (req, res) => {
    const { fullName, email, password } = req.body;
    if (!fullName || !email || !password)
        return res.status(400).json({ message: "All fields are required." });

    db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, row) => {
        if (err) {
            console.error("Signup DB check error:", err.message);
            return res.status(500).json({ message: "Internal server error." });
        }
        if (row)
            return res.status(409).json({ message: "User already exists." });

        try {
            const hashedPassword = await bcrypt.hash(password, 10);
            db.run(
                `INSERT INTO users (fullName, email, password, profileImageURL) VALUES (?, ?, ?, ?)`,
                [fullName, email, hashedPassword, null],
                function (err) {
                    if (err) {
                        console.error("Signup DB insert error:", err.message);
                        return res
                            .status(500)
                            .json({ message: "Error saving user." });
                    }
                    res.status(201).json({
                        message: "User registered successfully!",
                    });
                },
            );
        } catch (hashErr) {
            console.error("Bcrypt hashing error:", hashErr.message);
            res.status(500).json({ message: "Password hashing failed." });
        }
    });
});

// DELETE Story
app.delete("/api/stories/:storyId", isAuthenticated, (req, res) => {
    const storyId = parseInt(req.params.storyId);
    const userId = req.session.userId;

    if (isNaN(storyId)) {
        return res.status(400).json({ message: "Invalid story ID." });
    }

    taskDB.get(
        `SELECT userId FROM published_stories WHERE id = ?`,
        [storyId],
        (err, row) => {
            if (err) {
                console.error("Error checking story ownership:", err.message);
                return res.status(500).json({ message: "Internal server error." });
            }
            if (!row) {
                return res.status(404).json({ message: "Story not found." });
            }
            if (row.userId !== userId) {
                return res.status(403).json({ message: "Unauthorized." });
            }

            taskDB.run(
                `DELETE FROM published_stories WHERE id = ? AND userId = ?`,
                [storyId, userId],
                function (err) {
                    if (err) return res.status(500).json({ message: "Failed to delete story." });
                    res.status(200).json({ message: "Story deleted successfully." });
                },
            );
        },
    );
});

// User Login
app.post("/api/login", async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password)
        return res.status(400).json({ message: "Email and password are required." });

    db.get(
        `SELECT * FROM users WHERE email = ?`,
        [email],
        async (err, user) => {
            if (err) return res.status(500).json({ message: "Internal error." });
            if (!user || !(await bcrypt.compare(password, user.password)))
                return res.status(400).json({ message: "Invalid credentials." });

            req.session.userId = user.id;
            req.session.isLoggedIn = true;
            req.session.profileImageURL = user.profileImageURL;
            req.session.save((err) => {
                if (err) return res.status(500).json({ message: "Login successful, but session saving failed." });
                res.status(200).json({ message: "Login successful", redirect: "/home.html" });
            });
        },
    );
});

// User Logout
app.get("/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) return res.status(500).json({ message: "Logout error." });
        res.redirect("/pages/login.html");
    });
});

// Session Status Check
app.get("/api/session-status", (req, res) => {
    if (req.session.isLoggedIn && req.session.userId) {
        res.json({ loggedIn: true, userId: req.session.userId });
    } else {
        res.json({ loggedIn: false });
    }
});

// User Profile Data
app.get("/api/user-profile", isAuthenticated, (req, res) => {
    const userId = req.session.userId;
    db.get(
        `SELECT fullName, email, dateOfJoin, profileImageURL FROM users WHERE id = ?`,
        [userId],
        (err, user) => {
            if (err) return res.status(500).json({ message: "Error fetching profile" });
            if (!user) return res.status(404).json({ message: "User not found" });
            
            taskDB.get(
                `SELECT COUNT(*) as count FROM follows WHERE followingId = ?`,
                [userId],
                (err, followers) => {
                    if (err) return res.status(500).json({ message: "Error fetching profile data" });
                    
                    taskDB.get(
                        `SELECT COUNT(*) as count FROM follows WHERE followerId = ?`,
                        [userId],
                        (err, following) => {
                            if (err) return res.status(500).json({ message: "Error fetching profile data" });
                            res.json({
                                fullName: user.fullName,
                                email: user.email,
                                dateOfJoin: user.dateOfJoin,
                                profileImageURL: user.profileImageURL,
                                followersCount: followers.count,
                                followingCount: following.count,
                            });
                        },
                    );
                },
            );
        },
    );
});

// Update Username
app.post("/api/user/profile/update-username", isAuthenticated, (req, res) => {
    const userId = req.session.userId;
    const { username } = req.body;
    if (!username || typeof username !== "string" || username.trim() === "") {
        return res.status(400).json({ message: "Username cannot be empty." });
    }
    db.get(
        `SELECT id FROM users WHERE fullName = ? AND id != ?`,
        [username.trim(), userId],
        (err, row) => {
            if (err) return res.status(500).json({ message: "Internal server error." });
            if (row) return res.status(409).json({ message: "This username is already taken." });
            
            db.run(
                `UPDATE users SET fullName = ? WHERE id = ?`,
                [username.trim(), userId],
                function (err) {
                    if (err) return res.status(500).json({ message: "Failed to update username." });
                    res.status(200).json({
                        message: "Username updated successfully!",
                        newUsername: username.trim(),
                    });
                },
            );
        },
    );
});

// Upload Profile Image to S3
app.post("/api/upload-profile-image", isAuthenticated, async (req, res) => {
    const userId = req.session.userId;
    const { base64Image, fileExtension } = req.body;

    if (!base64Image || !fileExtension) {
        return res.status(400).json({ message: "Image data required." });
    }

    const allowedExtensions = ["png", "jpeg", "jpg", "gif"];
    if (!allowedExtensions.includes(fileExtension.toLowerCase())) {
        return res.status(400).json({ message: "Unsupported file format." });
    }

    const base64Data = base64Image.replace(/^data:image\/\w+;base64,/, "");
    const imageBuffer = Buffer.from(base64Data, "base64");
    const fileName = `profile-images/${userId}-${uuidv4()}.${fileExtension}`;

    const uploadParams = {
        Bucket: S3_BUCKET_NAME,
        Key: fileName,
        Body: imageBuffer,
        ContentType: `image/${fileExtension}`,
    };
    try {
        if (!S3_BUCKET_NAME || !AWS_REGION || !AWS_ACCESS_KEY_ID || !AWS_SECRET_ACCESS_KEY) {
            return res.status(500).json({ message: "S3 configuration error." });
        }
        await s3Client.send(new PutObjectCommand(uploadParams));
        const imageUrl = `https://${S3_BUCKET_NAME}.s3.${AWS_REGION}.amazonaws.com/${fileName}`;

        db.run(
            "UPDATE users SET profileImageURL = ? WHERE id = ?",
            [imageUrl, userId],
            function (err) {
                if (err) return res.status(500).json({ message: "Database update failed." });
                req.session.profileImageURL = imageUrl;
                res.status(200).json({ message: "Profile image updated!", imageUrl: imageUrl });
            },
        );
    } catch (s3Error) {
        console.error("Error uploading image to S3:", s3Error);
        res.status(500).json({ message: "Upload failed." });
    }
});

// Upload Story Image
app.post("/api/upload-story-image", isAuthenticated, async (req, res) => {
    // ... [Logic is identical to save-story image upload, kept for backward compatibility if needed]
    const userId = req.session.userId;
    const { storyId, base64Image, fileExtension } = req.body;

    if (!storyId || !base64Image || !fileExtension) return res.status(400).json({ message: "Missing data." });

    const base64Data = base64Image.replace(/^data:image\/\w+;base64,/, "");
    const imageBuffer = Buffer.from(base64Data, "base64");
    const fileName = `story-images/${userId}-${storyId}-${uuidv4()}.${fileExtension}`;

    const uploadParams = {
        Bucket: S3_BUCKET_NAME,
        Key: fileName,
        Body: imageBuffer,
        ContentType: `image/${fileExtension}`,
    };

    try {
        await s3Client.send(new PutObjectCommand(uploadParams));
        const imageUrl = `https://${S3_BUCKET_NAME}.s3.${AWS_REGION}.amazonaws.com/${fileName}`;

        taskDB.run(
            "UPDATE published_stories SET image = ? WHERE id = ? AND userId = ?",
            [imageUrl, storyId, userId],
            function (err) {
                if (err) return res.status(500).json({ message: "DB update failed." });
                res.status(200).json({ message: "Story image updated!", imageUrl: imageUrl });
            },
        );
    } catch (s3Error) {
        res.status(500).json({ message: "Upload failed." });
    }
});

// Search Users
app.get("/api/search-users", isAuthenticated, (req, res) => {
    const search = req.query.q;
    const currentUserId = req.session.userId;

    if (!search) return res.json([]);

    const sql = `SELECT id, fullName, dateOfJoin, profileImageURL FROM users WHERE (fullName LIKE ? OR email LIKE ?) AND id != ?`;
    const params = [`%${search}%`, `%${search}%`, currentUserId];

    db.all(sql, params, (err, rows) => {
        if (err) return res.status(500).json({ message: "Search failed" });
        res.json(rows);
    });
});

// Fetch Other User Details
app.get("/api/user-details/:userId", isAuthenticated, (req, res) => {
    const id = parseInt(req.params.userId);
    const currentUserId = req.session.userId;

    if (isNaN(id)) return res.status(400).json({ message: "Invalid user ID." });

    db.get(
        `SELECT id, fullName, dateOfJoin, profileImageURL FROM users WHERE id = ?`,
        [id],
        (err, user) => {
            if (err || !user) return res.status(404).json({ message: "User not found" });

            taskDB.get(
                `SELECT COUNT(*) as count FROM follows WHERE followingId = ?`,
                [id],
                (err, followers) => {
                    taskDB.get(
                        `SELECT COUNT(*) as count FROM follows WHERE followerId = ?`,
                        [id],
                        (err, following) => {
                            taskDB.get(
                                `SELECT 1 FROM follows WHERE followerId = ? AND followingId = ?`,
                                [currentUserId, id],
                                (err, isFollowingRow) => {
                                    res.json({
                                        id: user.id,
                                        fullName: user.fullName,
                                        dateOfJoin: user.dateOfJoin,
                                        profileImageURL: user.profileImageURL,
                                        followersCount: followers.count,
                                        followingCount: following.count,
                                        isFollowing: !!isFollowingRow,
                                        isSelf: currentUserId === id,
                                    });
                                },
                            );
                        },
                    );
                },
            );
        },
    );
});

// Fetch Followers
app.get("/api/followers/:userId", isAuthenticated, (req, res) => {
    const targetUserId = parseInt(req.params.userId);
    taskDB.all(
        `SELECT followerId FROM follows WHERE followingId = ?`,
        [targetUserId],
        (err, rows) => {
            if (rows.length === 0) return res.json([]);
            const ids = rows.map((r) => r.followerId);
            const placeholders = ids.map(() => "?").join(",");
            db.all(
                `SELECT id, fullName, dateOfJoin, profileImageURL FROM users WHERE id IN (${placeholders})`,
                ids,
                (err, users) => res.json(users)
            );
        }
    );
});

// Fetch Following
app.get("/api/following/:userId", isAuthenticated, (req, res) => {
    const targetUserId = parseInt(req.params.userId);
    taskDB.all(
        `SELECT followingId FROM follows WHERE followerId = ?`,
        [targetUserId],
        (err, rows) => {
            if (rows.length === 0) return res.json([]);
            const ids = rows.map((r) => r.followingId);
            const placeholders = ids.map(() => "?").join(",");
            db.all(
                `SELECT id, fullName, dateOfJoin, profileImageURL FROM users WHERE id IN (${placeholders})`,
                ids,
                (err, users) => res.json(users)
            );
        }
    );
});

// Cron job
cron.schedule("0 0 1 * *", generateStoryPrompt);

// Get Current Story Prompt
app.get("/current-story", (req, res) => {
    res.json(currentStoryPrompt);
});

// Get All Prompts
app.get("/api/prompts", (req, res) => {
    taskDB.all(`SELECT * FROM prompts ORDER BY id DESC`, (err, rows) => {
        if (err) return res.status(500).json({ message: "Failed to fetch prompts" });
        res.json(rows);
    });
});

// Fetch Single Story
app.get("/api/story/:storyId", isAuthenticated, (req, res) => {
    const storyId = parseInt(req.params.storyId);
    const currentUserId = req.session.userId;

    taskDB.get(
        `
        SELECT
            ps.id,
            ps.userId,
            ps.storyTitle,
            ps.fullStoryContent,
            ps.image,
            ps.timestamp,
            u.fullName AS authorFullName,
            u.profileImageURL AS authorProfileImageURL
        FROM
            published_stories ps
        JOIN
            users_db.users u ON ps.userId = u.id
        WHERE
            ps.id = ? AND ps.status = 'published'
    `,
        [storyId],
        (err, story) => {
            if (err || !story) return res.status(404).json({ message: "Story not found." });

            taskDB.get(
                `SELECT COUNT(*) as likeCount FROM likes WHERE storyId = ?`,
                [storyId],
                (err, likeResult) => {
                    taskDB.get(
                        `SELECT 1 FROM likes WHERE storyId = ? AND userId = ?`,
                        [storyId, currentUserId],
                        (err, userLiked) => {
                            story.likeCount = likeResult.likeCount;
                            story.isLikedByCurrentUser = !!userLiked;
                            res.json(story);
                        },
                    );
                },
            );
        },
    );
});

// Like/Unlike/Comment logic (Standard SQLite implementations)
app.post("/api/like/:storyId", isAuthenticated, (req, res) => {
    const storyId = req.params.storyId;
    const userId = req.session.userId;
    taskDB.run(`INSERT OR IGNORE INTO likes (storyId, userId) VALUES (?, ?)`, [storyId, userId], function(err) {
        if (err) return res.status(500).json({message: "Error"});
        taskDB.get(`SELECT COUNT(*) as likeCount FROM likes WHERE storyId = ?`, [storyId], (err, r) => {
            res.json({ message: "Liked", likeCount: r.likeCount, isLikedByCurrentUser: true });
        });
    });
});

app.post("/api/unlike/:storyId", isAuthenticated, (req, res) => {
    const storyId = req.params.storyId;
    const userId = req.session.userId;
    taskDB.run(`DELETE FROM likes WHERE storyId = ? AND userId = ?`, [storyId, userId], function(err) {
        if (err) return res.status(500).json({message: "Error"});
        taskDB.get(`SELECT COUNT(*) as likeCount FROM likes WHERE storyId = ?`, [storyId], (err, r) => {
            res.json({ message: "Unliked", likeCount: r.likeCount, isLikedByCurrentUser: false });
        });
    });
});

app.post("/api/story/:storyId/comment", isAuthenticated, (req, res) => {
    taskDB.run(`INSERT INTO comments (storyId, userId, commentText) VALUES (?, ?, ?)`, 
        [req.params.storyId, req.session.userId, req.body.commentText], 
        function(err) {
            if (err) return res.status(500).json({message: "Error"});
            res.status(201).json({message: "Comment added"});
        });
});

app.get("/api/story/:storyId/comments", isAuthenticated, (req, res) => {
    taskDB.all(`SELECT c.*, u.fullName AS authorFullName, u.profileImageURL AS authorProfileImageURL FROM comments c JOIN users_db.users u ON c.userId = u.id WHERE c.storyId = ? ORDER BY c.timestamp ASC`, 
    [req.params.storyId], (err, rows) => {
        res.json(rows);
    });
});

// Save Story (Draft/Publish)
app.post("/api/save-story", isAuthenticated, async (req, res) => {
    const { storyId, storyTitle, userWrittenContent, status, base64Image, fileExtension } = req.body;
    const userId = req.session.userId;

    const currentPromptText = currentStoryPrompt.prompt || "";
    const fullStoryContentWithPrompt = currentPromptText ? `"${currentPromptText}"\n\n${userWrittenContent}` : userWrittenContent;
    let imageUrl = "https://placehold.co/300x200/556B2F/FFFFFF?text=Story";

    try {
        if (base64Image && fileExtension) {
            const buffer = Buffer.from(base64Image.replace(/^data:image\/\w+;base64,/, ""), "base64");
            const fileName = `story-images/${userId}-${uuidv4()}.${fileExtension}`;
            await s3Client.send(new PutObjectCommand({
                Bucket: S3_BUCKET_NAME, Key: fileName, Body: buffer, ContentType: `image/${fileExtension}`
            }));
            imageUrl = `https://${S3_BUCKET_NAME}.s3.${AWS_REGION}.amazonaws.com/${fileName}`;
        }

        if (storyId) {
            taskDB.run(`UPDATE published_stories SET storyTitle=?, fullStoryContent=?, image=?, status=? WHERE id=? AND userId=?`,
                [storyTitle, fullStoryContentWithPrompt, imageUrl, status, storyId, userId],
                function(err) {
                    if (err) return res.status(500).json({message: "Update failed"});
                    res.json({message: "Updated", storyId, imageUrl});
                });
        } else {
            taskDB.run(`INSERT INTO published_stories (userId, storyTitle, fullStoryContent, image, status) VALUES (?, ?, ?, ?, ?)`,
                [userId, storyTitle, fullStoryContentWithPrompt, imageUrl, status],
                function(err) {
                    if (err) return res.status(500).json({message: "Create failed"});
                    res.status(201).json({message: "Created", storyId: this.lastID, imageUrl});
                });
        }
    } catch (e) {
        console.error(e);
        res.status(500).json({message: "Save failed"});
    }
});

// Follow/Unfollow
app.post("/api/follow/:userId", isAuthenticated, (req, res) => {
    taskDB.run(`INSERT OR IGNORE INTO follows (followerId, followingId) VALUES (?, ?)`, [req.session.userId, req.params.userId], function(err) {
        res.json({status: "followed"});
    });
});

app.post("/api/unfollow/:userId", isAuthenticated, (req, res) => {
    taskDB.run(`DELETE FROM follows WHERE followerId=? AND followingId=?`, [req.session.userId, req.params.userId], function(err) {
        res.json({status: "unfollowed"});
    });
});

// Feeds
app.get("/api/user-published-stories/:userId", isAuthenticated, (req, res) => {
    taskDB.all(`SELECT * FROM published_stories WHERE userId=? AND status='published' ORDER BY timestamp DESC`, [req.params.userId], (err, rows) => res.json(rows));
});

app.get("/api/followed-stories", isAuthenticated, (req, res) => {
    taskDB.all(`SELECT followingId FROM follows WHERE followerId=?`, [req.session.userId], (err, rows) => {
        if(rows.length === 0) return res.json([]);
        const ids = rows.map(r => r.followingId).join(",");
        taskDB.all(`SELECT ps.*, u.fullName as authorName, u.profileImageURL as authorProfileImageURL FROM published_stories ps JOIN users_db.users u ON ps.userId = u.id WHERE ps.userId IN (${ids}) AND ps.status='published' ORDER BY ps.timestamp DESC LIMIT 10`, [], (err, stories) => res.json(stories));
    });
});

app.get("/api/all-stories", isAuthenticated, async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const offset = (page - 1) * limit;
    const userId = req.session.userId;
    
    // Simplistic pagination for example
    taskDB.all(`SELECT ps.*, u.fullName as authorName, (SELECT COUNT(*) FROM likes WHERE storyId=ps.id) as likesCount FROM published_stories ps JOIN users_db.users u ON ps.userId = u.id WHERE ps.status='published' AND ps.userId != ? ORDER BY ps.timestamp DESC LIMIT ? OFFSET ?`, [userId, limit, offset], (err, rows) => {
        res.json({stories: rows, hasMore: rows.length === limit});
    });
});

// Static Files
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.get("/home.html", isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, "pages", "home.html")));
app.get("/pages/*", isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, "pages", req.params[0]))); // Generic handler
app.use("/assets", express.static(path.join(__dirname, "assets")));
app.use("/pages", express.static(path.join(__dirname, "pages")));
app.use(express.static(__dirname));

// Start
app.listen(port, () => {
    console.log(`🚀 Server running at http://localhost:${port}`);
});

process.on("SIGINT", () => {
    db.close();
    taskDB.close();
    process.exit(0);
});