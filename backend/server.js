const express = require("express");
const http = require("http");
const socketIo = require("socket.io");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "http://localhost:3000",
        methods: ["GET", "POST"],
    },
});

app.use(cors());
app.use(express.json());

// MongoDB Connection
mongoose
    .connect("mongodb://localhost:27017/whatsapp-clone", {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    })
    .then(() => console.log("MongoDB connected"))
    .catch((err) => console.error("MongoDB connection error:", err));

// Define Schemas
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    avatar: { type: String },
    createdAt: { type: Date, default: Date.now },
});

const messageSchema = new mongoose.Schema({
    from: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    to: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    text: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
    read: { type: Boolean, default: false },
});

const User = mongoose.model("User", userSchema);
const Message = mongoose.model("Message", messageSchema);

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) return res.status(401).json({ message: "Access denied" });

    jwt.verify(token, "YOUR_JWT_SECRET", (err, user) => {
        if (err) return res.status(403).json({ message: "Invalid token" });
        req.user = user;
        next();
    });
};

// Auth Routes
app.post("/api/auth/register", async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({
            $or: [{ username }, { email }],
        });
        if (existingUser) {
            return res
                .status(400)
                .json({ message: "Username or email already exists" });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create new user
        const user = new User({
            username,
            email,
            password: hashedPassword,
        });

        await user.save();
        res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Server error" });
    }
});

app.post("/api/auth/login", async (req, res) => {
    try {
        const { username, password } = req.body;

        // Find user
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ message: "Invalid credentials" });
        }

        // Validate password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Invalid credentials" });
        }

        // Generate JWT
        const token = jwt.sign({ id: user._id }, "YOUR_JWT_SECRET", {
            expiresIn: "24h",
        });

        res.status(200).json({
            id: user._id,
            username: user.username,
            email: user.email,
            avatar: user.avatar,
            token,
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Server error" });
    }
});

// API Routes
app.get("/api/contacts", authenticateToken, async (req, res) => {
    try {
        const users = await User.find({ _id: { $ne: req.user.id } }).select(
            "-password"
        );

        const formattedUsers = users.map((user) => ({
            id: user._id,
            name: user.username,
            avatar: user.avatar,
        }));

        res.status(200).json(formattedUsers);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Server error" });
    }
});

app.get("/api/messages/:contactId", authenticateToken, async (req, res) => {
    try {
        const messages = await Message.find({
            $or: [
                { from: req.user.id, to: req.params.contactId },
                { from: req.params.contactId, to: req.user.id },
            ],
        }).sort({ timestamp: 1 });

        const formattedMessages = messages.map((message) => ({
            id: message._id,
            from: message.from.toString(),
            to: message.to.toString(),
            text: message.text,
            timestamp: message.timestamp,
            read: message.read,
        }));

        res.status(200).json(formattedMessages);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Server error" });
    }
});

// Socket.io setup
const connectedUsers = {};

io.on("connection", (socket) => {
    console.log("New client connected");

    socket.on("user-connected", (user) => {
        connectedUsers[socket.id] = user;
        io.emit("user-list", Object.values(connectedUsers));
    });

    socket.on("send-message", async (message) => {
        try {
            // Save message to database
            const newMessage = new Message({
                from: message.from,
                to: message.to,
                text: message.text,
                timestamp: message.timestamp,
            });

            await newMessage.save();

            // Send to recipient if online
            const recipientSocketId = Object.keys(connectedUsers).find(
                (key) => connectedUsers[key].id === message.to
            );

            if (recipientSocketId) {
                io.to(recipientSocketId).emit("message-received", message);
            }
        } catch (error) {
            console.error("Error saving message:", error);
        }
    });

    socket.on("disconnect", () => {
        delete connectedUsers[socket.id];
        io.emit("user-list", Object.values(connectedUsers));
        console.log("Client disconnected");
    });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
