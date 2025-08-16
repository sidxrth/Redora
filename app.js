require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const session = require('express-session');
// const sqlite3 = require('sqlite3').verbose(); // REMOVE: No longer using SQLite3
// const SQLiteStore = require('connect-sqlite3')(session); // REMOVE: No longer using SQLiteStore
const MySQLStore = require('express-mysql-session')(session); // ADD: MySQL session store
const mysql = require('mysql2/promise'); // ADD: MySQL2 driver with promises
const cron = require('node-cron');
const cors = require('cors');
const axios = require('axios');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const { v4: uuidv4 } = require('uuid');

const app = express();
const port = 3000;

// AWS S3 Configuration (keep as is)
const AWS_ACCESS_KEY_ID = process.env.AWS_ACCESS_KEY_ID;
const AWS_SECRET_ACCESS_KEY = process.env.AWS_SECRET_ACCESS_KEY;
const AWS_REGION = process.env.AWS_REGION || 'ap-south-1';
const S3_BUCKET_NAME = process.env.S3_BUCKET_NAME;

const s3Client = new S3Client({
    region: AWS_REGION,
    credentials: {
        accessKeyId: AWS_ACCESS_KEY_ID,
        secretAccessKey: AWS_SECRET_ACCESS_KEY,
    }
});

// Middleware (keep as is, except for session store)
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// --- MySQL Database Configuration ---
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'story_app_user',
    password: process.env.DB_PASSWORD || 'your_strong_password', // Use environment variable for production
    database: process.env.DB_NAME || 'story_app_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

let pool; // Declare pool globally

async function connectToDatabase() {
    try {
        pool = mysql.createPool(dbConfig);
        console.log('✅ Connected to MySQL database pool.');

        // Test connection
        await pool.query('SELECT 1 + 1 AS solution');
        console.log('MySQL connection test successful.');

        // Create tables if they don't exist
        await createTables(pool);

    } catch (err) {
        console.error('❌ Failed to connect to MySQL or create tables:', err.message);
        process.exit(1); // Exit if database connection fails
    }
}

// Function to create tables (using pool for consistency)
async function createTables(dbConnection) {
    try {
        // Users table
        await dbConnection.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                fullName VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                dateOfJoin TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                profileImageURL VARCHAR(255) DEFAULT NULL
            )
        `);
        console.log('Users table ready.');

        // Prompts table
        await dbConnection.query(`
            CREATE TABLE IF NOT EXISTS prompts (
                id INT AUTO_INCREMENT PRIMARY KEY,
                month VARCHAR(50),
                prompt TEXT,
                dateGenerated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('Prompts table ready.');
        // Call generateStoryPrompt here after tables are ready
        generateStoryPrompt();

        // Published Stories table
        await dbConnection.query(`
            CREATE TABLE IF NOT EXISTS published_stories (
                id INT AUTO_INCREMENT PRIMARY KEY,
                userId INT NOT NULL,
                storyTitle VARCHAR(255) NOT NULL,
                fullStoryContent TEXT NOT NULL,
                image VARCHAR(255) DEFAULT 'https://placehold.co/300x200/556B2F/FFFFFF?text=Story',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status VARCHAR(50) DEFAULT 'draft' NOT NULL,
                FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
            )
        `);
        console.log('Published stories table ready.');

        // Follows table
        await dbConnection.query(`
            CREATE TABLE IF NOT EXISTS follows (
                followerId INT NOT NULL,
                followingId INT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (followerId, followingId),
                FOREIGN KEY (followerId) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (followingId) REFERENCES users(id) ON DELETE CASCADE
            )
        `);
        console.log('Follows table ready.');

        // Likes table
        await dbConnection.query(`
            CREATE TABLE IF NOT EXISTS likes (
                id INT AUTO_INCREMENT PRIMARY KEY,
                storyId INT NOT NULL,
                userId INT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (storyId, userId),
                FOREIGN KEY (storyId) REFERENCES published_stories(id) ON DELETE CASCADE,
                FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
            )
        `);
        console.log('Likes table ready.');

        // Comments table
        await dbConnection.query(`
            CREATE TABLE IF NOT EXISTS comments (
                id INT AUTO_INCREMENT PRIMARY KEY,
                storyId INT NOT NULL,
                userId INT NOT NULL,
                commentText TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (storyId) REFERENCES published_stories(id) ON DELETE CASCADE,
                FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
            )
        `);
        console.log('Comments table ready.');

    } catch (err) {
        console.error('❌ Error creating MySQL tables:', err.message);
        throw err; // Re-throw to be caught by connectToDatabase
    }
}

// Session setup with MySQLStore
const sessionStore = new MySQLStore({}, pool); // Pass the pool directly

app.use(session({
    secret: process.env.SESSION_SECRET || 'a_very_strong_and_random_secret_key_for_sessions', // Use environment variable
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Set to true if using HTTPS in production
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24 // 24 hours
    }
}));


// OpenRouter API for prompt generation (keep as is)
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
const openRouterClient = axios.create({
    baseURL: "https://openrouter.ai/api/v1",
    headers: {
        Authorization: `Bearer ${OPENROUTER_API_KEY}`,
        "Content-Type": "application/json"
    }
});

let currentStoryPrompt = {
    month: "",
    prompt: "",
    dateGenerated: ""
};

// Function to generate story prompt
async function generateStoryPrompt() {
    const date = new Date();
    const currentMonth = date.toLocaleString("default", { month: "long", year: "numeric" });

    try {
        // Check if prompt for current month exists in DB
        const [rows] = await pool.query(`SELECT * FROM prompts WHERE month = ?`, [currentMonth]);
        const row = rows[0];

        if (row) {
            currentStoryPrompt = {
                month: row.month,
                prompt: row.prompt,
                dateGenerated: row.dateGenerated
            };
            console.log("✅ Loaded existing prompt from DB:", currentStoryPrompt);
        } else {
            // Generate new prompt if not found
            if (!OPENROUTER_API_KEY) {
                console.error("❌ OpenRouter API Key is not set. Cannot generate new prompt.");
                currentStoryPrompt = {
                    month: currentMonth,
                    prompt: "Write a story about a hidden portal found in an old library...", // Fallback
                    dateGenerated: new Date().toISOString()
                };
                console.warn("Using fallback prompt due to missing API Key.");
                return;
            }

            try {
                console.log("Attempting to generate a new story prompt...");
                const response = await openRouterClient.post("/chat/completions", {
                    model: "mistralai/mistral-7b-instruct",
                    messages: [
                        {
                            role: "user",
                            content: "Write only the first 2–3 lines of a short, imaginative story for teenagers. Keep it engaging and under 50 words."
                        }
                    ],
                    temperature: 0.7,
                    max_tokens: 60
                });

                const prompt = response.data.choices[0].message.content.trim();
                const dateGenerated = date.toISOString();
                currentStoryPrompt = {
                    month: currentMonth,
                    prompt,
                    dateGenerated
                };

                // Save new prompt to DB
                await pool.query(`
                    INSERT INTO prompts (month, prompt, dateGenerated)
                    VALUES (?, ?, ?)
                `, [currentMonth, prompt, dateGenerated]);
                console.log("✅ New prompt saved to DB.");
            } catch (apiErr) {
                console.error("❌ API error during prompt generation:", apiErr.response?.data || apiErr.message);
                currentStoryPrompt = {
                    month: currentMonth,
                    prompt: "Write a story about a hidden portal found in an old library...", // Fallback
                    dateGenerated: new Date().toISOString()
                };
                console.warn("Using fallback prompt due to API error.");
            }
        }
    } catch (err) {
        console.error("❌ Error generating/loading story prompt:", err.message);
        // Fallback in case of DB error
        currentStoryPrompt = {
            month: currentMonth,
            prompt: "Write a story about a hidden portal found in an old library...", // Fallback
            dateGenerated: new Date().toISOString()
        };
        console.warn("Using fallback prompt due to database error during prompt generation.");
    }
}


// Authentication Middleware (keep as is)
function isAuthenticated(req, res, next) {
    if (req.session.isLoggedIn && req.session.userId) {
        next();
    } else {
        res.redirect('/pages/login.html');
    }
}

// --- API Endpoints ---

// User Registration
app.post('/api/register', async (req, res) => {
    const { fullName, email, password } = req.body;
    if (!fullName || !email || !password)
        return res.status(400).json({ message: 'All fields are required.' });

    try {
        const [rows] = await pool.query(`SELECT * FROM users WHERE email = ?`, [email]);
        if (rows.length > 0) return res.status(409).json({ message: 'User already exists.' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await pool.query(`INSERT INTO users (fullName, email, password, profileImageURL) VALUES (?, ?, ?, ?)`,
            [fullName, email, hashedPassword, null]);
        res.status(201).json({ message: 'User registered successfully!' });
    } catch (err) {
        console.error('Signup error:', err.message);
        res.status(500).json({ message: 'Internal server error.' });
    }
});

// User Login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password)
        return res.status(400).json({ message: 'Email and password are required.' });

    try {
        const [rows] = await pool.query(`SELECT * FROM users WHERE email = ?`, [email]);
        const user = rows[0];

        if (!user || !(await bcrypt.compare(password, user.password)))
            return res.status(400).json({ message: 'Invalid credentials.' });

        req.session.userId = user.id;
        req.session.isLoggedIn = true;
        req.session.profileImageURL = user.profileImageURL;
        req.session.save((err) => {
            if (err) {
                console.error('Error saving session after login:', err.message);
                return res.status(500).json({ message: 'Login successful, but session saving failed.' });
            }
            res.status(200).json({ message: 'Login successful', redirect: '/home.html' });
        });
    } catch (err) {
        console.error('Login error:', err.message);
        res.status(500).json({ message: 'Internal error.' });
    }
});

// User Logout (keep as is)
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Logout error:', err.message);
            return res.status(500).json({ message: 'Logout error.' });
        }
        res.redirect('/pages/login.html');
    });
});

// Session Status Check (keep as is)
app.get('/api/session-status', (req, res) => {
    if (req.session.isLoggedIn && req.session.userId) {
        res.json({ loggedIn: true, userId: req.session.userId });
    } else {
        res.json({ loggedIn: false });
    }
});

// User Profile Data
app.get('/api/user-profile', isAuthenticated, async (req, res) => {
    const userId = req.session.userId;
    try {
        const [userRows] = await pool.query(`SELECT fullName, email, dateOfJoin, profileImageURL FROM users WHERE id = ?`, [userId]);
        const user = userRows[0];
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const [followersResult] = await pool.query(`SELECT COUNT(*) as count FROM follows WHERE followingId = ?`, [userId]);
        const [followingResult] = await pool.query(`SELECT COUNT(*) as count FROM follows WHERE followerId = ?`, [userId]);

        res.json({
            fullName: user.fullName,
            email: user.email,
            dateOfJoin: user.dateOfJoin,
            profileImageURL: user.profileImageURL,
            followersCount: followersResult[0].count,
            followingCount: followingResult[0].count
        });
    } catch (err) {
        console.error('Error fetching profile:', err.message);
        res.status(500).json({ message: 'Error fetching profile' });
    }
});

// Update Username
app.post('/api/user/profile/update-username', isAuthenticated, async (req, res) => {
    const userId = req.session.userId;
    const { username } = req.body;
    if (!username || typeof username !== 'string' || username.trim() === '') {
        return res.status(400).json({ message: 'Username cannot be empty.' });
    }
    try {
        const [existingUserRows] = await pool.query(`SELECT id FROM users WHERE fullName = ? AND id != ?`, [username.trim(), userId]);
        if (existingUserRows.length > 0) {
            return res.status(409).json({ message: 'This username is already taken. Please choose a different one.' });
        }

        const [result] = await pool.query(`UPDATE users SET fullName = ? WHERE id = ?`, [username.trim(), userId]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'User not found or no changes made.' });
        }
        console.log(`User ${userId} updated username to: ${username.trim()}`);
        res.status(200).json({ message: 'Username updated successfully!', newUsername: username.trim() });
    } catch (err) {
        console.error('Error updating username:', err.message);
        res.status(500).json({ message: 'Failed to update username.' });
    }
});

// Upload Profile Image to S3 (keep as is, no DB changes here, only API calls)
app.post('/api/upload-profile-image', isAuthenticated, async (req, res) => {
    const userId = req.session.userId;
    const { base64Image, fileExtension } = req.body;

    if (!base64Image || !fileExtension) {
        return res.status(400).json({ message: 'Image data and file extension are required.' });
    }

    const allowedExtensions = ['png', 'jpeg', 'jpg', 'gif'];
    if (!allowedExtensions.includes(fileExtension.toLowerCase())) {
        return res.status(400).json({ message: 'Unsupported file format.' });
    }

    const base64Data = base64Image.replace(/^data:image\/\w+;base64,/, "");
    const imageBuffer = Buffer.from(base64Data, 'base64');
    const fileName = `profile-images/${userId}-${uuidv4()}.${fileExtension}`; // Unique name

    const uploadParams = {
        Bucket: S3_BUCKET_NAME,
        Key: fileName,
        Body: imageBuffer,
        ContentType: `image/${fileExtension}`,
        // ACL: 'public-read' // Consider if you truly need public-read ACL, or if pre-signed URLs are better
    };
    try {
        if (!S3_BUCKET_NAME || !AWS_REGION || !AWS_ACCESS_KEY_ID || !AWS_SECRET_ACCESS_KEY) {
            console.error("AWS S3 environment variables are not fully configured.");
            return res.status(500).json({ message: 'Server-side S3 configuration error. Please ensure AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION, and S3_BUCKET_NAME are set.' });
        }
        await s3Client.send(new PutObjectCommand(uploadParams));
        const imageUrl = `https://${S3_BUCKET_NAME}.s3.${AWS_REGION}.amazonaws.com/${fileName}`;
        console.log(`Uploaded image for user ${userId} to S3: ${imageUrl}`);

        const [result] = await pool.query("UPDATE users SET profileImageURL = ? WHERE id = ?", [imageUrl, userId]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'User not found or no changes made to database.' });
        }
        req.session.profileImageURL = imageUrl; // Update session
        res.status(200).json({ message: 'Profile image uploaded and updated successfully!', imageUrl: imageUrl });
    } catch (s3Error) {
        console.error("Error uploading image to S3:", s3Error);
        if (s3Error.name === 'NoSuchBucket') {
            return res.status(500).json({ message: 'Failed to upload image to S3: S3 bucket not found or incorrect name. Check S3_BUCKET_NAME.' });
        } else if (s3Error.name === 'AccessDenied') {
            return res.status(500).json({ message: 'Failed to upload image to S3: Access denied. Check AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and S3 bucket policy for s3:PutObject permissions.' });
        } else if (s3Error.message && (s3Error.message.includes('InvalidAccessKeyId') || s3Error.message.includes('SignatureDoesNotMatch'))) {
            return res.status(500).json({ message: 'Failed to upload image to S3: Invalid AWS credentials. Check AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.' });
        } else {
            return res.status(500).json({ message: `Failed to upload image to S3: ${s3Error.message || 'An unknown error occurred.'} Please check server logs.` });
        }
    }
});

// Upload Story Image to S3 (separate endpoint, kept for clarity though save-story now handles it)
app.post('/api/upload-story-image', isAuthenticated, async (req, res) => {
    const userId = req.session.userId;
    const { storyId, base64Image, fileExtension } = req.body;

    if (!storyId || !base64Image || !fileExtension) {
        return res.status(400).json({ message: 'Story ID, image data, and file extension are required.' });
    }

    const allowedExtensions = ['png', 'jpeg', 'jpg', 'gif'];
    if (!allowedExtensions.includes(fileExtension.toLowerCase())) {
        return res.status(400).json({ message: 'Unsupported file format.' });
    }

    const base64Data = base64Image.replace(/^data:image\/\w+;base64,/, "");
    const imageBuffer = Buffer.from(base64Data, 'base64');
    const fileName = `story-images/${userId}-${storyId}-${uuidv4()}.${fileExtension}`; // Unique name

    const uploadParams = {
        Bucket: S3_BUCKET_NAME,
        Key: fileName,
        Body: imageBuffer,
        ContentType: `image/${fileExtension}`,
        // ACL: 'public-read'
    };

    try {
        if (!S3_BUCKET_NAME || !AWS_REGION || !AWS_ACCESS_KEY_ID || !AWS_SECRET_ACCESS_KEY) {
            console.error("AWS S3 environment variables are not fully configured.");
            return res.status(500).json({ message: 'Server-side S3 configuration error. Please ensure AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION, and S3_BUCKET_NAME are set.' });
        }

        await s3Client.send(new PutObjectCommand(uploadParams));
        const imageUrl = `https://${S3_BUCKET_NAME}.s3.${AWS_REGION}.amazonaws.com/${fileName}`;
        console.log(`Uploaded image for story ${storyId} by user ${userId} to S3: ${imageUrl}`);

        // Update the story's image URL in the database
        const [result] = await pool.query("UPDATE published_stories SET image = ? WHERE id = ? AND userId = ?", [imageUrl, storyId, userId]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Story not found or user not authorized to update this story.' });
        }
        res.status(200).json({ message: 'Story image uploaded and updated successfully!', imageUrl: imageUrl });
    } catch (s3Error) {
        console.error("Error uploading image to S3:", s3Error);
        if (s3Error.name === 'NoSuchBucket') {
            return res.status(500).json({ message: 'Failed to upload image to S3: S3 bucket not found or incorrect name. Check S3_BUCKET_NAME.' });
        } else if (s3Error.name === 'AccessDenied') {
            return res.status(500).json({ message: 'Failed to upload image to S3: Access denied. Check AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and S3 bucket policy for s3:PutObject permissions.' });
        } else if (s3Error.message && (s3Error.message.includes('InvalidAccessKeyId') || s3Error.message.includes('SignatureDoesNotMatch'))) {
            return res.status(500).json({ message: 'Failed to upload image to S3: Invalid AWS credentials. Check AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.' });
        } else {
            return res.status(500).json({ message: `Failed to upload image to S3: ${s3Error.message || 'An unknown error occurred.'} Please check server logs.` });
        }
    }
});


// Search Users
app.get('/api/search-users', isAuthenticated, async (req, res) => {
    const search = req.query.q;
    const currentUserId = req.session.userId;

    if (!search) {
        return res.json([]);
    }

    try {
        const sql = `SELECT id, fullName, dateOfJoin, profileImageURL FROM users WHERE (fullName LIKE ? OR email LIKE ?) AND id != ?`;
        const params = [`%${search}%`, `%${search}%`, currentUserId];
        const [rows] = await pool.query(sql, params);
        res.json(rows);
    } catch (err) {
        console.error('Error during search query:', err.message);
        res.status(500).json({ message: 'Search failed' });
    }
});

// Fetch Other User Details
app.get('/api/user-details/:userId', isAuthenticated, async (req, res) => {
    const id = parseInt(req.params.userId);
    const currentUserId = req.session.userId;

    if (isNaN(id)) {
        return res.status(400).json({ message: 'Invalid user ID.' });
    }

    try {
        const [userRows] = await pool.query(`SELECT id, fullName, dateOfJoin, profileImageURL FROM users WHERE id = ?`, [id]);
        const user = userRows[0];
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const [followersResult] = await pool.query(`SELECT COUNT(*) as count FROM follows WHERE followingId = ?`, [id]);
        const [followingResult] = await pool.query(`SELECT COUNT(*) as count FROM follows WHERE followerId = ?`, [id]);
        const [isFollowingRows] = await pool.query(`SELECT 1 FROM follows WHERE followerId = ? AND followingId = ?`, [currentUserId, id]);

        res.json({
            id: user.id,
            fullName: user.fullName,
            dateOfJoin: user.dateOfJoin,
            profileImageURL: user.profileImageURL,
            followersCount: followersResult[0].count,
            followingCount: followingResult[0].count,
            isFollowing: isFollowingRows.length > 0,
            isSelf: (currentUserId === id)
        });
    } catch (err) {
        console.error('Fetch other user profile error:', err.message);
        res.status(500).json({ message: 'Fetch error' });
    }
});

// Fetch Followers for a User
app.get('/api/followers/:userId', isAuthenticated, async (req, res) => {
    const targetUserId = parseInt(req.params.userId);

    if (isNaN(targetUserId)) {
        return res.status(400).json({ message: 'Invalid user ID.' });
    }

    try {
        const [followerRows] = await pool.query(`SELECT followerId FROM follows WHERE followingId = ?`, [targetUserId]);
        if (followerRows.length === 0) {
            return res.status(200).json([]);
        }

        const followerIds = followerRows.map(row => row.followerId);
        const placeholders = followerIds.map(() => '?').join(',');

        const [users] = await pool.query(`SELECT id, fullName, dateOfJoin, profileImageURL FROM users WHERE id IN (${placeholders})`, followerIds);
        res.json(users);
    } catch (err) {
        console.error('Error fetching follower details:', err.message);
        res.status(500).json({ message: 'Failed to fetch followers.' });
    }
});

// Fetch Users a User is Following
app.get('/api/following/:userId', isAuthenticated, async (req, res) => {
    const targetUserId = parseInt(req.params.userId);

    if (isNaN(targetUserId)) {
        return res.status(400).json({ message: 'Invalid user ID.' });
    }

    try {
        const [followingRows] = await pool.query(`SELECT followingId FROM follows WHERE followerId = ?`, [targetUserId]);
        if (followingRows.length === 0) {
            return res.status(200).json([]);
        }

        const followingIds = followingRows.map(row => row.followingId);
        const placeholders = followingIds.map(() => '?').join(',');

        const [users] = await pool.query(`SELECT id, fullName, dateOfJoin, profileImageURL FROM users WHERE id IN (${placeholders})`, followingIds);
        res.json(users);
    } catch (err) {
        console.error('Error fetching followed user details:', err.message);
        res.status(500).json({ message: 'Failed to fetch followed user details.' });
    }
});

// Cron job to generate monthly story prompt (keep as is)
cron.schedule("0 0 1 * *", generateStoryPrompt); // Runs at midnight on the 1st of every month

// Get Current Story Prompt
app.get('/current-story', (req, res) => {
    res.json(currentStoryPrompt);
});

// Get All Prompts
app.get('/api/prompts', async (req, res) => {
    try {
        const [rows] = await pool.query(`SELECT * FROM prompts ORDER BY id DESC`);
        res.json(rows);
    } catch (err) {
        console.error('Failed to fetch prompts:', err.message);
        res.status(500).json({ message: 'Failed to fetch prompts' });
    }
});

// Fetch Single Story Details (Updated to include like data)
app.get('/api/story/:storyId', isAuthenticated, async (req, res) => {
    const storyId = parseInt(req.params.storyId);
    const currentUserId = req.session.userId;

    if (isNaN(storyId)) {
        return res.status(400).json({ message: 'Invalid story ID.' });
    }

    try {
        const [storyRows] = await pool.query(`
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
                users u ON ps.userId = u.id
            WHERE
                ps.id = ? AND ps.status = 'published'
        `, [storyId]);
        const story = storyRows[0];
        if (!story) {
            return res.status(404).json({ message: 'Story not found or not published.' });
        }

        // Get like count
        const [likeResult] = await pool.query(`SELECT COUNT(*) as likeCount FROM likes WHERE storyId = ?`, [storyId]);

        // Check if current user has liked this story
        const [userLikedRows] = await pool.query(`SELECT 1 FROM likes WHERE storyId = ? AND userId = ?`, [storyId, currentUserId]);

        story.likeCount = likeResult[0].likeCount;
        story.isLikedByCurrentUser = userLikedRows.length > 0; // Convert to boolean

        res.json(story);
    } catch (err) {
        console.error('Error fetching story:', err.message);
        res.status(500).json({ message: 'Failed to fetch story.' });
    }
});

// Like a Story
app.post('/api/like/:storyId', isAuthenticated, async (req, res) => {
    const storyId = parseInt(req.params.storyId);
    const userId = req.session.userId;

    if (isNaN(storyId)) {
        return res.status(400).json({ message: 'Invalid story ID.' });
    }

    try {
        const [insertResult] = await pool.query(`INSERT IGNORE INTO likes (storyId, userId) VALUES (?, ?)`, [storyId, userId]);

        // Get updated like count
        const [likeResult] = await pool.query(`SELECT COUNT(*) as likeCount FROM likes WHERE storyId = ?`, [storyId]);

        res.status(200).json({
            message: insertResult.affectedRows > 0 ? 'Story liked successfully!' : 'Already liked this story.',
            likeCount: likeResult[0].likeCount,
            isLikedByCurrentUser: true
        });
    } catch (err) {
        console.error('Error liking story:', err.message);
        res.status(500).json({ message: 'Failed to like story.' });
    }
});

// Unlike a Story
app.post('/api/unlike/:storyId', isAuthenticated, async (req, res) => {
    const storyId = parseInt(req.params.storyId);
    const userId = req.session.userId;

    if (isNaN(storyId)) {
        return res.status(400).json({ message: 'Invalid story ID.' });
    }

    try {
        const [deleteResult] = await pool.query(`DELETE FROM likes WHERE storyId = ? AND userId = ?`, [storyId, userId]);

        // Get updated like count
        const [likeResult] = await pool.query(`SELECT COUNT(*) as likeCount FROM likes WHERE storyId = ?`, [storyId]);

        res.status(200).json({
            message: deleteResult.affectedRows > 0 ? 'Story unliked successfully!' : 'Not liked this story.',
            likeCount: likeResult[0].likeCount,
            isLikedByCurrentUser: false
        });
    } catch (err) {
        console.error('Error unliking story:', err.message);
        res.status(500).json({ message: 'Failed to unlike story.' });
    }
});

// Add a Comment to a Story
app.post('/api/story/:storyId/comment', isAuthenticated, async (req, res) => {
    const storyId = parseInt(req.params.storyId);
    const userId = req.session.userId;
    const { commentText } = req.body;

    if (isNaN(storyId) || !commentText || commentText.trim() === '') {
        return res.status(400).json({ message: 'Invalid story ID or empty comment.' });
    }

    try {
        const [result] = await pool.query(`INSERT INTO comments (storyId, userId, commentText) VALUES (?, ?, ?)`,
            [storyId, userId, commentText.trim()]);
        res.status(201).json({ message: 'Comment added successfully!', commentId: result.insertId });
    } catch (err) {
        console.error('Error adding comment:', err.message);
        res.status(500).json({ message: 'Failed to add comment.' });
    }
});

// Get Comments for a Story
app.get('/api/story/:storyId/comments', isAuthenticated, async (req, res) => {
    const storyId = parseInt(req.params.storyId);

    if (isNaN(storyId)) {
        return res.status(400).json({ message: 'Invalid story ID.' });
    }

    try {
        const [comments] = await pool.query(`
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
                users u ON c.userId = u.id
            WHERE
                c.storyId = ?
            ORDER BY
                c.timestamp ASC
        `, [storyId]);
        res.json(comments);
    } catch (err) {
        console.error('Error fetching comments:', err.message);
        res.status(500).json({ message: 'Failed to fetch comments.' });
    }
});


// Save Story (Draft or Publish) with S3 Image Upload
app.post('/api/save-story', isAuthenticated, async (req, res) => {
    const { storyId, storyTitle, userWrittenContent, status, base64Image, fileExtension } = req.body;
    const userId = req.session.userId;

    if (!storyTitle || !userWrittenContent || !status) {
        return res.status(400).json({ message: 'Story title, content, and status are required.' });
    }
    if (!userId) {
        return res.status(401).json({ message: 'User not authenticated.' });
    }

    const currentPromptText = currentStoryPrompt.prompt || "";
    const fullStoryContentWithPrompt = currentPromptText ?
                                         `"${currentPromptText}"\n\n${userWrittenContent}` :
                                         userWrittenContent;

    let imageUrl = 'https://placehold.co/300x200/556B2F/FFFFFF?text=Story'; // Default image, will be overwritten if image uploaded

    try {
        // Handle Image Upload if base64Image is provided
        if (base64Image && fileExtension) {
            const allowedExtensions = ['png', 'jpeg', 'jpg', 'gif'];
            if (!allowedExtensions.includes(fileExtension.toLowerCase())) {
                return res.status(400).json({ message: 'Unsupported file format for image.' });
            }

            const base64Data = base64Image.replace(/^data:image\/\w+;base64,/, "");
            const imageBuffer = Buffer.from(base64Data, 'base64');

            const uniqueFileName = `story-images/${userId}-${uuidv4()}.${fileExtension}`;

            const uploadParams = {
                Bucket: S3_BUCKET_NAME,
                Key: uniqueFileName,
                Body: imageBuffer,
                ContentType: `image/${fileExtension}`,
            };

            if (!S3_BUCKET_NAME || !AWS_REGION || !AWS_ACCESS_KEY_ID || !AWS_SECRET_ACCESS_KEY) {
                console.error("AWS S3 environment variables are not fully configured. Please check your .env file.");
                return res.status(500).json({ message: 'Server-side S3 configuration error. Please ensure AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION, and S3_BUCKET_NAME are set in your .env file.' });
            }

            console.log(`Attempting to upload image for user ${userId} to S3...`);
            await s3Client.send(new PutObjectCommand(uploadParams));
            imageUrl = `https://${S3_BUCKET_NAME}.s3.${AWS_REGION}.amazonaws.com/${uniqueFileName}`;
            console.log(`Uploaded image to S3: ${imageUrl}`);
        }

        // Save/Update Story in Database
        if (storyId) { // Logic for updating an existing story
            const [result] = await pool.query(`
                UPDATE published_stories
                SET storyTitle = ?, fullStoryContent = ?, image = ?, status = ?
                WHERE id = ? AND userId = ?
            `, [storyTitle, fullStoryContentWithPrompt, imageUrl, status, storyId, userId]);

            if (result.affectedRows === 0) {
                return res.status(404).json({ message: 'Story not found or user not authorized to update this story.' });
            }
            res.status(200).json({ message: `Story ${status} successfully updated!`, storyId: storyId, imageUrl: imageUrl });
        } else { // Logic for inserting a new story
            const [result] = await pool.query(`
                INSERT INTO published_stories (userId, storyTitle, fullStoryContent, image, status, timestamp)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            `, [userId, storyTitle, fullStoryContentWithPrompt, imageUrl, status]);
            res.status(201).json({ message: `Story ${status} successfully!`, storyId: result.insertId, imageUrl: imageUrl });
        }

    } catch (dbOrS3Error) {
        console.error("Error during S3 upload or DB operation in /api/save-story:", dbOrS3Error);
        // Distinguish S3 errors from DB errors if needed, but for now, catch all
        if (dbOrS3Error.name === 'NoSuchBucket') {
            return res.status(500).json({ message: 'Failed to upload image to S3: S3 bucket not found or incorrect name. Check S3_BUCKET_NAME in your .env file.' });
        } else if (dbOrS3Error.name === 'AccessDenied') {
            return res.status(500).json({ message: 'Failed to upload image to S3: Access denied. Check AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and S3 bucket policy for s3:PutObject permissions.' });
        } else if (dbOrS3Error.message && (dbOrS3Error.message.includes('InvalidAccessKeyId') || dbOrS3Error.message.includes('SignatureDoesNotMatch'))) {
            return res.status(500).json({ message: 'Failed to upload image to S3: Invalid AWS credentials. Check AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in your .env file.' });
        } else {
            return res.status(500).json({ message: `Failed to save story: ${dbOrS3Error.message || 'An unknown error occurred.'} Please check server logs.` });
        }
    }
});

// Follow User
app.post('/api/follow/:userId', isAuthenticated, async (req, res) => {
    const followerId = req.session.userId;
    const followingId = parseInt(req.params.userId);

    if (isNaN(followingId)) {
        return res.status(400).json({ message: 'Invalid user ID.' });
    }
    if (followerId === followingId) {
        return res.status(400).json({ message: 'You cannot follow yourself.' });
    }

    try {
        const [result] = await pool.query(`INSERT IGNORE INTO follows (followerId, followingId) VALUES (?, ?)`,
            [followerId, followingId]);
        if (result.affectedRows > 0) {
            res.status(200).json({ message: 'User followed successfully!', status: 'followed' });
        } else {
            res.status(200).json({ message: 'Already following this user.', status: 'already_followed' });
        }
    } catch (err) {
        console.error('Error following user:', err.message);
        res.status(500).json({ message: 'Failed to follow user.' });
    }
});

// Unfollow User
app.post('/api/unfollow/:userId', isAuthenticated, async (req, res) => {
    const followerId = req.session.userId;
    const followingId = parseInt(req.params.userId);

    if (isNaN(followingId)) {
        return res.status(400).json({ message: 'Invalid user ID.' });
    }
    if (followerId === followingId) {
        return res.status(400).json({ message: 'You cannot unfollow yourself (or follow yourself).' });
    }

    try {
        const [result] = await pool.query(`DELETE FROM follows WHERE followerId = ? AND followingId = ?`,
            [followerId, followingId]);
        if (result.affectedRows > 0) {
            res.status(200).json({ message: 'User unfollowed successfully!', status: 'unfollowed' });
        } else {
            res.status(404).json({ message: 'You are not following this user.', status: 'not_following' });
        }
    } catch (err) {
        console.error('Error unfollowing user:', err.message);
        res.status(500).json({ message: 'Failed to unfollow user.' });
    }
});

// Fetch User's Published Stories
app.get('/api/user-published-stories/:userId', isAuthenticated, async (req, res) => {
    const userId = parseInt(req.params.userId);

    if (isNaN(userId)) {
        return res.status(400).json({ message: 'Invalid user ID.' });
    }

    try {
        const [rows] = await pool.query(`SELECT id, storyTitle, fullStoryContent, image, timestamp FROM published_stories WHERE userId = ? AND status = 'published' ORDER BY timestamp DESC`,
            [userId]);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching user published stories:', err.message);
        res.status(500).json({ message: 'Failed to fetch user stories.' });
    }
});

// NEW: Fetch Stories from Followed Users (Corrected endpoint path)
app.get('/api/followed-stories', isAuthenticated, async (req, res) => {
    const currentUserId = req.session.userId;

    try {
        const [followingRows] = await pool.query(`SELECT followingId FROM follows WHERE followerId = ?`, [currentUserId]);

        if (followingRows.length === 0) {
            return res.status(200).json([]);
        }

        const followingIds = followingRows.map(row => row.followingId);
        const placeholders = followingIds.map(() => '?').join(',');

        const [stories] = await pool.query(`
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
                users u ON ps.userId = u.id
            WHERE
                ps.userId IN (${placeholders}) AND ps.status = 'published'
            ORDER BY
                ps.timestamp DESC
            LIMIT 10
        `, followingIds);
        res.json(stories);
    } catch (err) {
        console.error('Error fetching followed users stories:', err.message);
        res.status(500).json({ message: 'Failed to fetch stories from followed users.' });
    }
});


// Serve HTML Pages (protected by isAuthenticated where applicable)
// These should be defined before any generic static file serving middleware.
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/home.html', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'pages', 'home.html')));
app.get('/pages/userpage.html', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'pages', 'userpage.html')));
app.get('/pages/edit.html', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'pages', 'edit.html')));
app.get('/pages/search.html', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'pages', 'search.html')));
app.get('/pages/other.html', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'pages', 'other.html')));
app.get('/story.html', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'pages', 'aigen', 'story.html'));
});
app.get('/pages/functions/view_story.html', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'pages', 'functions', 'view_story.html')));
app.get('/pages/follow/followers.html', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'pages', 'follow', 'followers.html')));
app.get('/pages/follow/following.html', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'pages', 'follow', 'following.html')));


// Serve static assets - these should come after all specific API and HTML routes
app.use('/assets', express.static(path.join(__dirname, 'assets')));
app.use('/pages', express.static(path.join(__dirname, 'pages')));
app.use('/pages/follow', express.static(path.join(__dirname, 'pages', 'follow')));
app.use(express.static(__dirname)); // Fallback for root static files

// 404 Not Found Handler - This must be the absolute last handler
app.use((req, res) => {
    if (req.accepts('html')) {
        res.status(404).sendFile(path.join(__dirname, 'pages', '404.html'));
    } else if (req.accepts('json')) {
        res.status(404).json({ error: 'Not Found', message: `API endpoint '${req.originalUrl}' not found.` });
    } else {
        res.status(404).send('Not Found');
    }
});


// Start the server
// Call connectToDatabase before starting the server
connectToDatabase().then(() => {
    app.listen(port, () => {
        console.log(`🚀 Server running at http://localhost:${port}`);
    });
});

// Graceful shutdown
process.on('SIGINT', async () => {
    console.log('Shutting down server...');
    if (pool) {
        await pool.end();
        console.log('Closed MySQL database pool.');
    }
    process.exit(0);
});