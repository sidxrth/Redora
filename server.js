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
app.use(express.json({ limit: "10mb" })); // Increased limit for image data
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// Session setup
app.use(
    session({
        secret: "a_very_strong_and_random_secret_key_for_sessions", // Use a strong, unique key
        resave: false,
        saveUninitialized: false,
        store: new SQLiteStore({
            db: "sessions.db",
            table: "sessions",
            dir: "./",
        }),
        cookie: {
            secure: false, // Set to true if using HTTPS
            httpOnly: true,
            maxAge: 1000 * 60 * 60 * 24, // 24 hours
        },
    }),
);

// Database setup for users
const DB_PATH = "./users.db"; // Path to users.db
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

// OpenRouter API for prompt generation
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
const openRouterClient = axios.create({
    baseURL: "https://openrouter.ai/api/v1",
    headers: {
        Authorization: `Bearer ${OPENROUTER_API_KEY}`,
        "Content-Type": "application/json",
    },
});

let currentStoryPrompt = {
    month: "",
    prompt: "",
    dateGenerated: "",
};

// Function to generate story prompt
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
                if (!OPENROUTER_API_KEY) {
                    console.error(
                        "❌ OpenRouter API Key is not set. Cannot generate new prompt.",
                    );
                    currentStoryPrompt = {
                        month: currentMonth,
                        prompt: "Write a story about a hidden portal found in an old library...", // Fallback
                        dateGenerated: new Date().toISOString(),
                    };
                    console.warn(
                        "Using fallback prompt due to missing API Key.",
                    );
                    return;
                }

                try {
                    console.log("Attempting to generate a new story prompt...");
                    const response = await openRouterClient.post(
                        "/chat/completions",
                        {
                            model: "mistralai/mistral-7b-instruct",
                            messages: [
                                {
                                    role: "user",
                                    content:
                                        "Write only the first 2–3 lines of a short, imaginative story for teenagers. Keep it engaging and under 50 words.",
                                },
                            ],
                            temperature: 0.7,
                            max_tokens: 60,
                        },
                    );

                    const prompt =
                        response.data.choices[0].message.content.trim();
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
                        prompt: "Write a story about a hidden portal found in an old library...", // Fallback
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

    // Attach users.db to this taskDB connection so it can see the 'users' table
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
            UNIQUE (storyId, userId), -- Ensures a user can only like a story once
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
    const userId = req.session.userId; // Get the ID of the logged-in user

    if (isNaN(storyId)) {
        return res.status(400).json({ message: "Invalid story ID." });
    }

    // First, verify that the story belongs to the logged-in user
    taskDB.get(
        `SELECT userId FROM published_stories WHERE id = ?`,
        [storyId],
        (err, row) => {
            if (err) {
                console.error("Error checking story ownership:", err.message);
                return res
                    .status(500)
                    .json({ message: "Internal server error." });
            }
            if (!row) {
                return res.status(404).json({ message: "Story not found." });
            }
            if (row.userId !== userId) {
                return res
                    .status(403)
                    .json({
                        message:
                            "Unauthorized: You can only delete your own stories.",
                    });
            }

            // If ownership is confirmed, proceed with deletion
            taskDB.run(
                `DELETE FROM published_stories WHERE id = ? AND userId = ?`,
                [storyId, userId],
                function (err) {
                    if (err) {
                        console.error(
                            "Error deleting story from DB:",
                            err.message,
                        );
                        return res
                            .status(500)
                            .json({ message: "Failed to delete story." });
                    }
                    if (this.changes === 0) {
                        return res
                            .status(404)
                            .json({
                                message:
                                    "Story not found or not owned by user.",
                            });
                    }
                    res.status(200).json({
                        message: "Story deleted successfully.",
                    });
                },
            );
        },
    );
});

// User Login
app.post("/api/login", async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password)
        return res
            .status(400)
            .json({ message: "Email and password are required." });

    db.get(
        `SELECT * FROM users WHERE email = ?`,
        [email],
        async (err, user) => {
            if (err) {
                console.error("Login DB error:", err.message);
                return res.status(500).json({ message: "Internal error." });
            }
            if (!user || !(await bcrypt.compare(password, user.password)))
                return res
                    .status(400)
                    .json({ message: "Invalid credentials." });

            req.session.userId = user.id;
            req.session.isLoggedIn = true;
            req.session.profileImageURL = user.profileImageURL;
            req.session.save((err) => {
                if (err) {
                    console.error(
                        "Error saving session after login:",
                        err.message,
                    );
                    return res
                        .status(500)
                        .json({
                            message:
                                "Login successful, but session saving failed.",
                        });
                }
                res.status(200).json({
                    message: "Login successful",
                    redirect: "/home.html",
                });
            });
        },
    );
});

// User Logout
app.get("/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error("Logout error:", err.message);
            return res.status(500).json({ message: "Logout error." });
        }
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
            if (err) {
                console.error("Error fetching profile:", err.message);
                return res
                    .status(500)
                    .json({ message: "Error fetching profile" });
            }
            if (!user) {
                return res.status(404).json({ message: "User not found" });
            }
            taskDB.get(
                `SELECT COUNT(*) as count FROM follows WHERE followingId = ?`,
                [userId],
                (err, followers) => {
                    if (err) {
                        console.error(
                            "Error fetching followers count:",
                            err.message,
                        );
                        return res
                            .status(500)
                            .json({ message: "Error fetching profile data" });
                    }
                    taskDB.get(
                        `SELECT COUNT(*) as count FROM follows WHERE followerId = ?`,
                        [userId],
                        (err, following) => {
                            if (err) {
                                console.error(
                                    "Error fetching following count:",
                                    err.message,
                                );
                                return res
                                    .status(500)
                                    .json({
                                        message: "Error fetching profile data",
                                    });
                            }
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
            if (err) {
                console.error("Error checking existing username:", err.message);
                return res
                    .status(500)
                    .json({ message: "Internal server error." });
            }
            if (row) {
                return res
                    .status(409)
                    .json({
                        message:
                            "This username is already taken. Please choose a different one.",
                    });
            }
            db.run(
                `UPDATE users SET fullName = ? WHERE id = ?`,
                [username.trim(), userId],
                function (err) {
                    if (err) {
                        console.error("Error updating username:", err.message);
                        return res
                            .status(500)
                            .json({ message: "Failed to update username." });
                    }
                    if (this.changes === 0) {
                        return res
                            .status(404)
                            .json({
                                message: "User not found or no changes made.",
                            });
                    }
                    console.log(
                        `User ${userId} updated username to: ${username.trim()}`,
                    );
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
        return res
            .status(400)
            .json({ message: "Image data and file extension are required." });
    }

    const allowedExtensions = ["png", "jpeg", "jpg", "gif"];
    if (!allowedExtensions.includes(fileExtension.toLowerCase())) {
        return res.status(400).json({ message: "Unsupported file format." });
    }

    const base64Data = base64Image.replace(/^data:image\/\w+;base64,/, "");
    const imageBuffer = Buffer.from(base64Data, "base64");
    const fileName = `profile-images/${userId}-${uuidv4()}.${fileExtension}`; // Unique name

    const uploadParams = {
        Bucket: S3_BUCKET_NAME,
        Key: fileName,
        Body: imageBuffer,
        ContentType: `image/${fileExtension}`,
        // ACL: 'public-read'
    };
    try {
        if (
            !S3_BUCKET_NAME ||
            !AWS_REGION ||
            !AWS_ACCESS_KEY_ID ||
            !AWS_SECRET_ACCESS_KEY
        ) {
            console.error(
                "AWS S3 environment variables are not fully configured.",
            );
            return res
                .status(500)
                .json({
                    message:
                        "Server-side S3 configuration error. Please ensure AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION, and S3_BUCKET_NAME are set.",
                });
        }
        await s3Client.send(new PutObjectCommand(uploadParams));
        const imageUrl = `https://${S3_BUCKET_NAME}.s3.${AWS_REGION}.amazonaws.com/${fileName}`;
        console.log(`Uploaded image for user ${userId} to S3: ${imageUrl}`);

        db.run(
            "UPDATE users SET profileImageURL = ? WHERE id = ?",
            [imageUrl, userId],
            function (err) {
                if (err) {
                    console.error(
                        "Database error updating profile image URL:",
                        err.message,
                    );
                    return res
                        .status(500)
                        .json({
                            message:
                                "Failed to update profile image URL in database.",
                        });
                }
                if (this.changes === 0) {
                    return res
                        .status(404)
                        .json({
                            message:
                                "User not found or no changes made to database.",
                        });
                }
                req.session.profileImageURL = imageUrl; // Update session
                res.status(200).json({
                    message: "Profile image uploaded and updated successfully!",
                    imageUrl: imageUrl,
                });
            },
        );
    } catch (s3Error) {
        console.error("Error uploading image to S3:", s3Error);
        if (s3Error.name === "NoSuchBucket") {
            return res
                .status(500)
                .json({
                    message:
                        "Failed to upload image to S3: S3 bucket not found or incorrect name. Check S3_BUCKET_NAME.",
                });
        } else if (s3Error.name === "AccessDenied") {
            return res
                .status(500)
                .json({
                    message:
                        "Failed to upload image to S3: Access denied. Check AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and S3 bucket policy for s3:PutObject permissions.",
                });
        } else if (
            s3Error.message &&
            (s3Error.message.includes("InvalidAccessKeyId") ||
                s3Error.message.includes("SignatureDoesNotMatch"))
        ) {
            return res
                .status(500)
                .json({
                    message:
                        "Failed to upload image to S3: Invalid AWS credentials. Check AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.",
                });
        } else {
            return res
                .status(500)
                .json({
                    message: `Failed to upload image to S3: ${s3Error.message || "An unknown error occurred."} Please check server logs.`,
                });
        }
    }
});

// Upload Story Image to S3 (separate endpoint, kept for clarity though save-story now handles it)
app.post("/api/upload-story-image", isAuthenticated, async (req, res) => {
    const userId = req.session.userId;
    const { storyId, base64Image, fileExtension } = req.body; // frontend should send storyId for existing stories

    if (!storyId || !base64Image || !fileExtension) {
        return res
            .status(400)
            .json({
                message:
                    "Story ID, image data, and file extension are required.",
            });
    }

    const allowedExtensions = ["png", "jpeg", "jpg", "gif"];
    if (!allowedExtensions.includes(fileExtension.toLowerCase())) {
        return res.status(400).json({ message: "Unsupported file format." });
    }

    const base64Data = base64Image.replace(/^data:image\/\w+;base64,/, "");
    const imageBuffer = Buffer.from(base64Data, "base64");
    const fileName = `story-images/${userId}-${storyId}-${uuidv4()}.${fileExtension}`; // Unique name

    const uploadParams = {
        Bucket: S3_BUCKET_NAME,
        Key: fileName,
        Body: imageBuffer,
        ContentType: `image/${fileExtension}`,
        // ACL: 'public-read'
    };

    try {
        if (
            !S3_BUCKET_NAME ||
            !AWS_REGION ||
            !AWS_ACCESS_KEY_ID ||
            !AWS_SECRET_ACCESS_KEY
        ) {
            console.error(
                "AWS S3 environment variables are not fully configured.",
            );
            return res
                .status(500)
                .json({
                    message:
                        "Server-side S3 configuration error. Please ensure AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION, and S3_BUCKET_NAME are set.",
                });
        }

        await s3Client.send(new PutObjectCommand(uploadParams));
        const imageUrl = `https://${S3_BUCKET_NAME}.s3.${AWS_REGION}.amazonaws.com/${fileName}`;
        console.log(
            `Uploaded image for story ${storyId} by user ${userId} to S3: ${imageUrl}`,
        );

        // Update the story's image URL in the database
        taskDB.run(
            "UPDATE published_stories SET image = ? WHERE id = ? AND userId = ?",
            [imageUrl, storyId, userId],
            function (err) {
                if (err) {
                    console.error(
                        "Database error updating story image URL:",
                        err.message,
                    );
                    return res
                        .status(500)
                        .json({
                            message:
                                "Failed to update story image URL in database.",
                        });
                }
                if (this.changes === 0) {
                    return res
                        .status(404)
                        .json({
                            message:
                                "Story not found or user not authorized to update this story.",
                        });
                }
                res.status(200).json({
                    message: "Story image uploaded and updated successfully!",
                    imageUrl: imageUrl,
                });
            },
        );
    } catch (s3Error) {
        console.error("Error uploading image to S3:", s3Error);
        if (s3Error.name === "NoSuchBucket") {
            return res
                .status(500)
                .json({
                    message:
                        "Failed to upload image to S3: S3 bucket not found or incorrect name. Check S3_BUCKET_NAME.",
                });
        } else if (s3Error.name === "AccessDenied") {
            return res
                .status(500)
                .json({
                    message:
                        "Failed to upload image to S3: Access denied. Check AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and S3 bucket policy for s3:PutObject permissions.",
                });
        } else if (
            s3Error.message &&
            (s3Error.message.includes("InvalidAccessKeyId") ||
                s3Error.message.includes("SignatureDoesNotMatch"))
        ) {
            return res
                .status(500)
                .json({
                    message:
                        "Failed to upload image to S3: Invalid AWS credentials. Check AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.",
                });
        } else {
            return res
                .status(500)
                .json({
                    message: `Failed to upload image to S3: ${s3Error.message || "An unknown error occurred."} Please check server logs.`,
                });
        }
    }
});

// Search Users
app.get("/api/search-users", isAuthenticated, (req, res) => {
    const search = req.query.q;
    const currentUserId = req.session.userId;

    if (!search) {
        return res.json([]);
    }

    const sql = `SELECT id, fullName, dateOfJoin, profileImageURL FROM users WHERE (fullName LIKE ? OR email LIKE ?) AND id != ?`;
    const params = [`%${search}%`, `%${search}%`, currentUserId];

    db.all(sql, params, (err, rows) => {
        if (err) {
            console.error("Error during search query:", err.message);
            return res.status(500).json({ message: "Search failed" });
        }
        res.json(rows);
    });
});

// Fetch Other User Details
app.get("/api/user-details/:userId", isAuthenticated, (req, res) => {
    const id = parseInt(req.params.userId);
    const currentUserId = req.session.userId;

    if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid user ID." });
    }

    db.get(
        `SELECT id, fullName, dateOfJoin, profileImageURL FROM users WHERE id = ?`,
        [id],
        (err, user) => {
            if (err) {
                console.error("Fetch other user profile error:", err.message);
                return res.status(500).json({ message: "Fetch error" });
            }
            if (!user) {
                return res.status(404).json({ message: "User not found" });
            }

            taskDB.get(
                `SELECT COUNT(*) as count FROM follows WHERE followingId = ?`,
                [id],
                (err, followers) => {
                    if (err) {
                        console.error(
                            "Error fetching followers count for other user:",
                            err.message,
                        );
                        return res
                            .status(500)
                            .json({ message: "Error fetching profile data" });
                    }
                    taskDB.get(
                        `SELECT COUNT(*) as count FROM follows WHERE followerId = ?`,
                        [id],
                        (err, following) => {
                            if (err) {
                                console.error(
                                    "Error fetching following count for other user:",
                                    err.message,
                                );
                                return res
                                    .status(500)
                                    .json({
                                        message: "Error fetching profile data",
                                    });
                            }
                            taskDB.get(
                                `SELECT 1 FROM follows WHERE followerId = ? AND followingId = ?`,
                                [currentUserId, id],
                                (err, isFollowingRow) => {
                                    if (err) {
                                        console.error(
                                            "Error checking follow status for other user:",
                                            err.message,
                                        );
                                        return res
                                            .status(500)
                                            .json({
                                                message:
                                                    "Error fetching profile data",
                                            });
                                    }
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

// Fetch Followers for a User
app.get("/api/followers/:userId", isAuthenticated, (req, res) => {
    const targetUserId = parseInt(req.params.userId);

    if (isNaN(targetUserId)) {
        return res.status(400).json({ message: "Invalid user ID." });
    }

    taskDB.all(
        `SELECT followerId FROM follows WHERE followingId = ?`,
        [targetUserId],
        (err, followerRows) => {
            if (err) {
                console.error("Error fetching follower IDs:", err.message);
                return res
                    .status(500)
                    .json({ message: "Failed to fetch followers." });
            }
            if (followerRows.length === 0) {
                return res.status(200).json([]);
            }

            const followerIds = followerRows.map((row) => row.followerId);
            const placeholders = followerIds.map(() => "?").join(",");

            db.all(
                `SELECT id, fullName, dateOfJoin, profileImageURL FROM users WHERE id IN (${placeholders})`,
                followerIds,
                (err, users) => {
                    if (err) {
                        console.error(
                            "Error fetching follower user details:",
                            err.message,
                        );
                        return res
                            .status(500)
                            .json({
                                message: "Failed to fetch follower details.",
                            });
                    }
                    res.json(users);
                },
            );
        },
    );
});

// Fetch Users a User is Following
app.get("/api/following/:userId", isAuthenticated, (req, res) => {
    const targetUserId = parseInt(req.params.userId);

    if (isNaN(targetUserId)) {
        return res.status(400).json({ message: "Invalid user ID." });
    }

    taskDB.all(
        `SELECT followingId FROM follows WHERE followerId = ?`,
        [targetUserId],
        (err, followingRows) => {
            if (err) {
                console.error("Error fetching following IDs:", err.message);
                return res
                    .status(500)
                    .json({ message: "Failed to fetch followed users." });
            }
            if (followingRows.length === 0) {
                return res.status(200).json([]);
            }

            const followingIds = followingRows.map((row) => row.followingId);
            const placeholders = followingIds.map(() => "?").join(",");

            db.all(
                `SELECT id, fullName, dateOfJoin, profileImageURL FROM users WHERE id IN (${placeholders})`,
                followingIds,
                (err, users) => {
                    if (err) {
                        console.error(
                            "Error fetching followed user details:",
                            err.message,
                        );
                        return res
                            .status(500)
                            .json({
                                message:
                                    "Failed to fetch followed user details.",
                            });
                    }
                    res.json(users);
                },
            );
        },
    );
});

// Cron job to generate monthly story prompt
cron.schedule("0 0 1 * *", generateStoryPrompt); // Runs at midnight on the 1st of every month

// Get Current Story Prompt
app.get("/current-story", (req, res) => {
    res.json(currentStoryPrompt);
});

// Get All Prompts
app.get("/api/prompts", (req, res) => {
    taskDB.all(`SELECT * FROM prompts ORDER BY id DESC`, (err, rows) => {
        if (err)
            return res.status(500).json({ message: "Failed to fetch prompts" });
        res.json(rows);
    });
});

// Fetch Single Story Details (Updated to include like data)
app.get("/api/story/:storyId", isAuthenticated, (req, res) => {
    const storyId = parseInt(req.params.storyId);
    const currentUserId = req.session.userId;

    if (isNaN(storyId)) {
        return res.status(400).json({ message: "Invalid story ID." });
    }

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
            if (err) {
                console.error("Error fetching story:", err.message);
                return res
                    .status(500)
                    .json({ message: "Failed to fetch story." });
            }
            if (!story) {
                return res
                    .status(404)
                    .json({ message: "Story not found or not published." });
            }

            // Get like count
            taskDB.get(
                `SELECT COUNT(*) as likeCount FROM likes WHERE storyId = ?`,
                [storyId],
                (err, likeResult) => {
                    if (err) {
                        console.error(
                            "Error fetching like count:",
                            err.message,
                        );
                        return res
                            .status(500)
                            .json({
                                message: "Failed to fetch story details.",
                            });
                    }

                    // Check if current user has liked this story
                    taskDB.get(
                        `SELECT 1 FROM likes WHERE storyId = ? AND userId = ?`,
                        [storyId, currentUserId],
                        (err, userLiked) => {
                            if (err) {
                                console.error(
                                    "Error checking user like status:",
                                    err.message,
                                );
                                return res
                                    .status(500)
                                    .json({
                                        message:
                                            "Failed to fetch story details.",
                                    });
                            }

                            story.likeCount = likeResult.likeCount;
                            story.isLikedByCurrentUser = !!userLiked; // Convert to boolean

                            res.json(story);
                        },
                    );
                },
            );
        },
    );
});

// Like a Story
app.post("/api/like/:storyId", isAuthenticated, (req, res) => {
    const storyId = parseInt(req.params.storyId);
    const userId = req.session.userId;

    if (isNaN(storyId)) {
        return res.status(400).json({ message: "Invalid story ID." });
    }

    taskDB.run(
        `INSERT OR IGNORE INTO likes (storyId, userId) VALUES (?, ?)`,
        [storyId, userId],
        function (err) {
            if (err) {
                console.error("Error liking story:", err.message);
                return res
                    .status(500)
                    .json({ message: "Failed to like story." });
            }
            // Get updated like count and current user's like status
            taskDB.get(
                `SELECT COUNT(*) as likeCount FROM likes WHERE storyId = ?`,
                [storyId],
                (err, likeResult) => {
                    if (err) {
                        console.error(
                            "Error fetching updated like count:",
                            err.message,
                        );
                        return res
                            .status(500)
                            .json({
                                message: "Failed to get updated like count.",
                            });
                    }
                    res.status(200).json({
                        message:
                            this.changes > 0
                                ? "Story liked successfully!"
                                : "Already liked this story.",
                        likeCount: likeResult.likeCount,
                        isLikedByCurrentUser: true, // After a like, it's always true for current user
                    });
                },
            );
        },
    );
});

// Unlike a Story
app.post("/api/unlike/:storyId", isAuthenticated, (req, res) => {
    const storyId = parseInt(req.params.storyId);
    const userId = req.session.userId;

    if (isNaN(storyId)) {
        return res.status(400).json({ message: "Invalid story ID." });
    }

    taskDB.run(
        `DELETE FROM likes WHERE storyId = ? AND userId = ?`,
        [storyId, userId],
        function (err) {
            if (err) {
                console.error("Error unliking story:", err.message);
                return res
                    .status(500)
                    .json({ message: "Failed to unlike story." });
            }
            // Get updated like count and current user's like status
            taskDB.get(
                `SELECT COUNT(*) as likeCount FROM likes WHERE storyId = ?`,
                [storyId],
                (err, likeResult) => {
                    if (err) {
                        console.error(
                            "Error fetching updated like count:",
                            err.message,
                        );
                        return res
                            .status(500)
                            .json({
                                message: "Failed to get updated like count.",
                            });
                    }
                    res.status(200).json({
                        message:
                            this.changes > 0
                                ? "Story unliked successfully!"
                                : "Not liked this story.",
                        likeCount: likeResult.likeCount,
                        isLikedByCurrentUser: false, // After an unlike, it's always false for current user
                    });
                },
            );
        },
    );
});

// Add a Comment to a Story
app.post("/api/story/:storyId/comment", isAuthenticated, (req, res) => {
    const storyId = parseInt(req.params.storyId);
    const userId = req.session.userId;
    const { commentText } = req.body;

    if (isNaN(storyId) || !commentText || commentText.trim() === "") {
        return res
            .status(400)
            .json({ message: "Invalid story ID or empty comment." });
    }

    taskDB.run(
        `INSERT INTO comments (storyId, userId, commentText) VALUES (?, ?, ?)`,
        [storyId, userId, commentText.trim()],
        function (err) {
            if (err) {
                console.error("Error adding comment:", err.message);
                return res
                    .status(500)
                    .json({ message: "Failed to add comment." });
            }
            res.status(201).json({
                message: "Comment added successfully!",
                commentId: this.lastID,
            });
        },
    );
});

// Get Comments for a Story
app.get("/api/story/:storyId/comments", isAuthenticated, (req, res) => {
    const storyId = parseInt(req.params.storyId);

    if (isNaN(storyId)) {
        return res.status(400).json({ message: "Invalid story ID." });
    }

    taskDB.all(
        `
        SELECT
            c.id,
            c.commentText,
            c.timestamp,
            u.id AS userId,
            u.fullName AS authorFullName,
            u.profileImageURL AS authorProfileImageURL
        FROM
            comments c
        JOIN
            users_db.users u ON c.userId = u.id
        WHERE
            c.storyId = ?
        ORDER BY
            c.timestamp ASC
    `,
        [storyId],
        (err, comments) => {
            if (err) {
                console.error("Error fetching comments:", err.message);
                return res
                    .status(500)
                    .json({ message: "Failed to fetch comments." });
            }
            res.json(comments);
        },
    );
});

// Save Story (Draft or Publish) with S3 Image Upload
app.post("/api/save-story", isAuthenticated, async (req, res) => {
    const {
        storyId,
        storyTitle,
        userWrittenContent,
        status,
        base64Image,
        fileExtension,
    } = req.body;
    const userId = req.session.userId;

    if (!storyTitle || !userWrittenContent || !status) {
        return res
            .status(400)
            .json({
                message: "Story title, content, and status are required.",
            });
    }
    if (!userId) {
        return res.status(401).json({ message: "User not authenticated." });
    }

    const currentPromptText = currentStoryPrompt.prompt || "";
    const fullStoryContentWithPrompt = currentPromptText
        ? `"${currentPromptText}"\n\n${userWrittenContent}`
        : userWrittenContent;

    let imageUrl = "https://placehold.co/300x200/556B2F/FFFFFF?text=Story"; // Default image, will be overwritten if image uploaded

    try {
        // Handle Image Upload if base64Image is provided
        if (base64Image && fileExtension) {
            const allowedExtensions = ["png", "jpeg", "jpg", "gif"];
            if (!allowedExtensions.includes(fileExtension.toLowerCase())) {
                return res
                    .status(400)
                    .json({ message: "Unsupported file format for image." });
            }

            const base64Data = base64Image.replace(
                /^data:image\/\w+;base64,/,
                "",
            );
            const imageBuffer = Buffer.from(base64Data, "base64");

            const uniqueFileName = `story-images/${userId}-${uuidv4()}.${fileExtension}`;

            const uploadParams = {
                Bucket: S3_BUCKET_NAME,
                Key: uniqueFileName,
                Body: imageBuffer,
                ContentType: `image/${fileExtension}`,
            };

            if (
                !S3_BUCKET_NAME ||
                !AWS_REGION ||
                !AWS_ACCESS_KEY_ID ||
                !AWS_SECRET_ACCESS_KEY
            ) {
                console.error(
                    "AWS S3 environment variables are not fully configured. Please check your .env file.",
                );
                return res
                    .status(500)
                    .json({
                        message:
                            "Server-side S3 configuration error. Please ensure AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION, and S3_BUCKET_NAME are set in your .env file.",
                    });
            }

            console.log(
                `Attempting to upload image for user ${userId} to S3...`,
            );
            await s3Client.send(new PutObjectCommand(uploadParams));
            imageUrl = `https://${S3_BUCKET_NAME}.s3.${AWS_REGION}.amazonaws.com/${uniqueFileName}`;
            console.log(`Uploaded image to S3: ${imageUrl}`);
        }

        // Save/Update Story in Database
        if (storyId) {
            // Logic for updating an existing story
            taskDB.run(
                `
                UPDATE published_stories
                SET storyTitle = ?, fullStoryContent = ?, image = ?, status = ?
                WHERE id = ? AND userId = ?
            `,
                [
                    storyTitle,
                    fullStoryContentWithPrompt,
                    imageUrl,
                    status,
                    storyId,
                    userId,
                ],
                function (err) {
                    if (err) {
                        console.error(
                            "Error updating story in DB:",
                            err.message,
                        );
                        return res
                            .status(500)
                            .json({ message: `Failed to update story.` });
                    }
                    if (this.changes === 0) {
                        return res
                            .status(404)
                            .json({
                                message:
                                    "Story not found or user not authorized to update this story.",
                            });
                    }
                    res.status(200).json({
                        message: `Story ${status} successfully updated!`,
                        storyId: storyId,
                        imageUrl: imageUrl,
                    });
                },
            );
        } else {
            // Logic for inserting a new story
            taskDB.run(
                `
                INSERT INTO published_stories (userId, storyTitle, fullStoryContent, image, status, timestamp)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            `,
                [
                    userId,
                    storyTitle,
                    fullStoryContentWithPrompt,
                    imageUrl,
                    status,
                ],
                function (err) {
                    if (err) {
                        console.error(
                            "Error saving new story to DB:",
                            err.message,
                        );
                        return res
                            .status(500)
                            .json({ message: `Failed to ${status} story.` });
                    }
                    res.status(201).json({
                        message: `Story ${status} successfully!`,
                        storyId: this.lastID,
                        imageUrl: imageUrl,
                    });
                },
            );
        }
    } catch (s3Error) {
        console.error("Error during S3 upload in /api/save-story:", s3Error);
        if (s3Error.name === "NoSuchBucket") {
            return res
                .status(500)
                .json({
                    message:
                        "Failed to upload image to S3: S3 bucket not found or incorrect name. Check S3_BUCKET_NAME in your .env file.",
                });
        } else if (s3Error.name === "AccessDenied") {
            return res
                .status(500)
                .json({
                    message:
                        "Failed to upload image to S3: Access denied. Check AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and S3 bucket policy for s3:PutObject permissions.",
                });
        } else if (
            s3Error.message &&
            (s3Error.message.includes("InvalidAccessKeyId") ||
                s3Error.message.includes("SignatureDoesNotMatch"))
        ) {
            return res
                .status(500)
                .json({
                    message:
                        "Failed to upload image to S3: Invalid AWS credentials. Check AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in your .env file.",
                });
        } else {
            return res
                .status(500)
                .json({
                    message: `Failed to upload image to S3: ${s3Error.message || "An unknown error occurred."} Please check server logs.`,
                });
        }
    }
});

// Follow User
app.post("/api/follow/:userId", isAuthenticated, (req, res) => {
    const followerId = req.session.userId;
    const followingId = parseInt(req.params.userId);

    if (isNaN(followingId)) {
        return res.status(400).json({ message: "Invalid user ID." });
    }
    if (followerId === followingId) {
        return res.status(400).json({ message: "You cannot follow yourself." });
    }

    taskDB.run(
        `INSERT OR IGNORE INTO follows (followerId, followingId) VALUES (?, ?)`,
        [followerId, followingId],
        function (err) {
            if (err) {
                console.error("Error following user:", err.message);
                return res
                    .status(500)
                    .json({ message: "Failed to follow user." });
            }
            if (this.changes > 0) {
                res.status(200).json({
                    message: "User followed successfully!",
                    status: "followed",
                });
            } else {
                res.status(200).json({
                    message: "Already following this user.",
                    status: "already_followed",
                });
            }
        },
    );
});

// Unfollow User
app.post("/api/unfollow/:userId", isAuthenticated, (req, res) => {
    const followerId = req.session.userId;
    const followingId = parseInt(req.params.userId);

    if (isNaN(followingId)) {
        return res.status(400).json({ message: "Invalid user ID." });
    }
    if (followerId === followingId) {
        return res
            .status(400)
            .json({
                message: "You cannot unfollow yourself (or follow yourself).",
            });
    }

    taskDB.run(
        `DELETE FROM follows WHERE followerId = ? AND followingId = ?`,
        [followerId, followingId],
        function (err) {
            if (err) {
                console.error("Error unfollowing user:", err.message);
                return res
                    .status(500)
                    .json({ message: "Failed to unfollow user." });
            }
            if (this.changes > 0) {
                res.status(200).json({
                    message: "User unfollowed successfully!",
                    status: "unfollowed",
                });
            } else {
                res.status(404).json({
                    message: "You are not following this user.",
                    status: "not_following",
                });
            }
        },
    );
});

// Fetch User's Published Stories
app.get("/api/user-published-stories/:userId", isAuthenticated, (req, res) => {
    const userId = parseInt(req.params.userId);

    if (isNaN(userId)) {
        return res.status(400).json({ message: "Invalid user ID." });
    }

    taskDB.all(
        `SELECT id, storyTitle, fullStoryContent, image, timestamp FROM published_stories WHERE userId = ? AND status = 'published' ORDER BY timestamp DESC`,
        [userId],
        (err, rows) => {
            if (err) {
                console.error(
                    "Error fetching user published stories:",
                    err.message,
                );
                return res
                    .status(500)
                    .json({ message: "Failed to fetch user stories." });
            }
            res.json(rows);
        },
    );
});

// NEW: Fetch Stories from Followed Users (Corrected endpoint path)
app.get("/api/followed-stories", isAuthenticated, (req, res) => {
    const currentUserId = req.session.userId;

    taskDB.all(
        `SELECT followingId FROM follows WHERE followerId = ?`,
        [currentUserId],
        (err, followingRows) => {
            if (err) {
                console.error(
                    "Error fetching following IDs for stories:",
                    err.message,
                );
                return res
                    .status(500)
                    .json({ message: "Failed to fetch followed users." });
            }

            if (followingRows.length === 0) {
                return res.status(200).json([]);
            }

            const followingIds = followingRows.map((row) => row.followingId);
            const placeholders = followingIds.map(() => "?").join(",");

            taskDB.all(
                `
            SELECT
                ps.id,
                ps.storyTitle AS title,
                ps.fullStoryContent AS content,
                ps.image AS coverImage,
                ps.timestamp,
                u.fullName AS authorName,
                u.profileImageURL AS authorProfileImageURL
            FROM
                published_stories ps
            JOIN
                users_db.users u ON ps.userId = u.id
            WHERE
                ps.userId IN (${placeholders}) AND ps.status = 'published'
            ORDER BY
                ps.timestamp DESC
            LIMIT 10
        `,
                followingIds,
                (err, stories) => {
                    if (err) {
                        console.error(
                            "Error fetching followed users stories:",
                            err.message,
                        );
                        return res
                            .status(500)
                            .json({
                                message:
                                    "Failed to fetch stories from followed users.",
                            });
                    }
                    res.json(stories);
                },
            );
        },
    );
});

// NEW: API to fetch all stories with pagination and sorting
app.get("/api/all-stories", isAuthenticated, async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const sort = req.query.sort || "recently_posted"; // 'recently_posted' or 'most_likes'
    const currentUserId = req.session.userId; // Get the ID of the logged-in user

    const offset = (page - 1) * limit;

    let orderByClause = "";
    // Note: likesCount is an alias from the subquery, so ORDER BY clause can directly use it.
    if (sort === "most_likes") {
        orderByClause = "ORDER BY likesCount DESC, ps.timestamp DESC";
    } else {
        // default to recently_posted
        orderByClause = "ORDER BY ps.timestamp DESC";
    }

    try {
        // Count total stories excluding the current user's
        const countSql =
            'SELECT COUNT(*) AS totalStories FROM published_stories WHERE status = "published" AND userId != ?';
        const totalStoriesResult = await new Promise((resolve, reject) => {
            taskDB.get(countSql, [currentUserId], (err, row) => {
                if (err) reject(err);
                resolve(row ? row.totalStories : 0); // Handle case where no published stories
            });
        });

        const sql = `
            SELECT
                ps.id,
                ps.storyTitle,
                ps.fullStoryContent,
                ps.image,
                ps.timestamp,
                u.fullName AS authorName,
                (SELECT COUNT(*) FROM likes WHERE storyId = ps.id) AS likesCount
            FROM published_stories ps
            JOIN users_db.users u ON ps.userId = u.id
            WHERE ps.status = 'published' AND ps.userId != ? -- Exclude current user's stories
            ${orderByClause}
            LIMIT ? OFFSET ?
        `;

        const stories = await new Promise((resolve, reject) => {
            taskDB.all(sql, [currentUserId, limit, offset], (err, rows) => {
                if (err) reject(err);
                resolve(rows);
            });
        });

        const hasMore = offset + stories.length < totalStoriesResult;

        res.json({ stories, hasMore, totalStories: totalStoriesResult });
    } catch (error) {
        console.error("Error fetching all stories:", error);
        res.status(500).json({
            message: "Internal server error while fetching stories.",
        });
    }
});

// Serve HTML Pages (protected by isAuthenticated where applicable)
// These should be defined before any generic static file serving middleware.
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.get("/home.html", isAuthenticated, (req, res) =>
    res.sendFile(path.join(__dirname, "pages", "home.html")),
);
app.get("/pages/userpage.html", isAuthenticated, (req, res) =>
    res.sendFile(path.join(__dirname, "pages", "userpage.html")),
);
app.get("/pages/edit.html", isAuthenticated, (req, res) =>
    res.sendFile(path.join(__dirname, "pages", "edit.html")),
);
app.get("/pages/search.html", isAuthenticated, (req, res) =>
    res.sendFile(path.join(__dirname, "pages", "search.html")),
);
app.get("/pages/other.html", isAuthenticated, (req, res) =>
    res.sendFile(path.join(__dirname, "pages", "other.html")),
);
app.get("/story.html", isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, "pages", "aigen", "story.html"));
});
app.get("/pages/functions/view_story.html", isAuthenticated, (req, res) =>
    res.sendFile(path.join(__dirname, "pages", "functions", "view_story.html")),
);
app.get("/pages/follow/followers.html", isAuthenticated, (req, res) =>
    res.sendFile(path.join(__dirname, "pages", "follow", "followers.html")),
);
app.get("/pages/follow/following.html", isAuthenticated, (req, res) =>
    res.sendFile(path.join(__dirname, "pages", "follow", "following.html")),
);
// NEW: Route for all_stories.html
app.get("/pages/all_stories.html", isAuthenticated, (req, res) =>
    res.sendFile(path.join(__dirname, "pages", "all_stories.html")),
);

// Serve static assets - these should come after all specific API and HTML routes
app.use("/assets", express.static(path.join(__dirname, "assets")));
app.use("/pages", express.static(path.join(__dirname, "pages")));
app.use(
    "/pages/follow",
    express.static(path.join(__dirname, "pages", "follow")),
);
app.use(express.static(__dirname)); // Fallback for root static files

// 404 Not Found Handler - This must be the absolute last handler
app.use((req, res) => {
    if (req.accepts("html")) {
        res.status(404).sendFile(path.join(__dirname, "pages", "404.html"));
    } else if (req.accepts("json")) {
        res.status(404).json({
            error: "Not Found",
            message: `API endpoint '${req.originalUrl}' not found.`,
        });
    } else {
        res.status(404).send("Not Found");
    }
});

// Start the server
app.listen(port, () => {
    console.log(`🚀 Server running at http://localhost:${port}`);
});

// Graceful shutdown
process.on("SIGINT", () => {
    console.log("Shutting down server...");
    db.close(() => console.log("Closed users.db"));
    taskDB.close(() => {
        console.log("Closed task.db");
        process.exit(0);
    });
});
