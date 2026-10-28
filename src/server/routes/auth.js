const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { ethers } = require('ethers');
const bcrypt = require('bcryptjs');
const db = require('../models/database');
const { authLimiter } = require('../middleware/rateLimiting');
const { authenticateToken } = require('../middleware/auth');
const { validateUserRegistration, validateUserLogin } = require('../middleware/validation');

function getJwtSecret() {
  const secret = process.env.JWT_SECRET;
  if (!secret || secret === 'fallback-secret') {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('JWT_SECRET must be configured');
    }
    return 'dev-only-insecure-secret';
  }
  return secret;
}

function signUserToken(user) {
  return jwt.sign(
    {
      userId: user.id,
      email: user.email,
      name: user.name,
      walletAddress: user.wallet?.address,
      roles: user.roles || ['buyer']
    },
    getJwtSecret(),
    { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
  );
}

// Mock user for authentication (in production, this would be a real user database)
const mockUser = {
  id: 'user1',
  email: 'demo@rwahub.com',
  password: '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password: 'password'
  name: 'Demo User',
  roles: ['buyer', 'seller']
};

// Seed the demo account so email Sign In works against the real /login route
if (!db.users.has(mockUser.id)) {
  db.users.set(mockUser.id, { ...mockUser, createdAt: new Date(), updatedAt: new Date() });
}

// --- Wallet sign-in: nonce challenge + signature verification ---
const WALLET_NONCE_TTL_MS = 5 * 60 * 1000;
const walletNonces = new Map(); // lowercased address -> { nonce, expiresAt }

const walletMessage = (address, nonce) =>
  `Sign in to RWAHub\nAddress: ${address}\nNonce: ${nonce}`;

function normalizeAddress(value) {
  try {
    return ethers.utils.getAddress(String(value));
  } catch {
    return null;
  }
}

router.post('/wallet/nonce', authLimiter, (req, res) => {
  const address = normalizeAddress(req.body?.address);
  if (!address) {
    return res.status(400).json({ error: 'A valid wallet address is required' });
  }
  const nonce = crypto.randomBytes(16).toString('hex');
  walletNonces.set(address.toLowerCase(), { nonce, expiresAt: Date.now() + WALLET_NONCE_TTL_MS });
  res.json({ nonce, message: walletMessage(address, nonce) });
});

router.post('/wallet', authLimiter, (req, res) => {
  try {
    const address = normalizeAddress(req.body?.address);
    const signature = req.body?.signature;
    if (!address || typeof signature !== 'string') {
      return res.status(400).json({ error: 'Wallet address and signature are required' });
    }

    const key = address.toLowerCase();
    const challenge = walletNonces.get(key);
    walletNonces.delete(key); // single use, even on failure
    if (!challenge || challenge.expiresAt < Date.now()) {
      return res.status(401).json({ error: 'Sign-in challenge expired. Request a new one.' });
    }

    let recovered;
    try {
      recovered = ethers.utils.verifyMessage(walletMessage(address, challenge.nonce), signature);
    } catch {
      return res.status(401).json({ error: 'Invalid wallet signature' });
    }
    if (recovered !== address) {
      return res.status(401).json({ error: 'Invalid wallet signature' });
    }

    let user = Array.from(db.users.values()).find(
      (candidate) => candidate.wallet?.address?.toLowerCase() === key
    );
    if (!user) {
      user = {
        id: `wallet_${key.slice(2, 14)}`,
        name: `${address.slice(0, 6)}...${address.slice(-4)}`,
        roles: ['buyer', 'seller'],
        wallet: { address, balance: 0, currency: 'USDT' },
        createdAt: new Date(),
        updatedAt: new Date()
      };
      db.users.set(user.id, user);
    }

    const { password: _, ...userResponse } = user;
    res.json({ user: userResponse, token: signUserToken(user), message: 'Wallet login successful' });
  } catch (error) {
    console.error('Error with wallet login:', error);
    res.status(500).json({ error: 'Failed to login with wallet' });
  }
});

// Register new user
router.post('/register', authLimiter, validateUserRegistration, async (req, res) => {
  try {
    const { email, password, name } = req.body;

    // Validate required fields
    if (!email || !password || !name) {
      return res.status(400).json({ 
        error: 'Missing required fields: email, password, name' 
      });
    }

    // Check if user already exists
    const existingUser = Array.from(db.users.values()).find(user => user.email === email);
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create new user
    const newUser = {
      id: `user_${Date.now()}`,
      email,
      password: hashedPassword,
      name,
      roles: ['buyer'],
      kyc: {
        status: 'pending',
        documents: {}
      },
      wallet: {
        address: `0x${Math.random().toString(16).substr(2, 40)}`,
        balance: 0,
        currency: 'USDT'
      },
      stats: {
        assetsListed: 0,
        assetsSold: 0,
        assetsBought: 0,
        totalValue: 0,
        rating: 0,
        reviews: 0
      },
      createdAt: new Date(),
      updatedAt: new Date()
    };

    // Store user (in production, save to database)
    db.users.set(newUser.id, newUser);

    // Generate JWT token
    const token = signUserToken(newUser);

    // Remove password from response
    const { password: _, ...userResponse } = newUser;

    res.status(201).json({
      user: userResponse,
      token,
      message: 'User registered successfully'
    });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ error: 'Failed to register user' });
  }
});

// Login user
router.post('/login', authLimiter, validateUserLogin, async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = Array.from(db.users.values()).find((candidate) => candidate.email === email);
    const passwordHash = user && user.password ? user.password : mockUser.password;
    const isValidPassword = await bcrypt.compare(password, passwordHash);
    if (!user || !user.password || !isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = signUserToken(user);

    // Remove password from response
    const { password: _, ...userResponse } = user;

    res.json({
      user: userResponse,
      token,
      message: 'Login successful'
    });
  } catch (error) {
    console.error('Error logging in user:', error);
    res.status(500).json({ error: 'Failed to login user' });
  }
});

// Get current user profile
router.get('/profile', authenticateToken, (req, res) => {
  try {
    const user = db.users.get(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    const { password: _, ...userResponse } = user;
    res.json(userResponse);
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).json({ error: 'Failed to fetch user profile' });
  }
});

// Update user profile
router.patch('/profile', authenticateToken, (req, res) => {
  try {
    const userId = req.user.userId;
    const user = db.users.get(userId);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const allowedFields = ['name'];
    const updates = {};
    for (const field of allowedFields) {
      if (req.body[field] !== undefined) {
        updates[field] = req.body[field];
      }
    }

    const updatedUser = {
      ...user,
      ...updates,
      id: user.id,
      email: user.email,
      password: user.password,
      roles: user.roles,
      updatedAt: new Date()
    };

    db.users.set(userId, updatedUser);
    
    const { password: _, ...userResponse } = updatedUser;
    res.json(userResponse);
  } catch (error) {
    console.error('Error updating user profile:', error);
    res.status(500).json({ error: 'Failed to update user profile' });
  }
});

router.post('/refresh', authLimiter, (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ error: 'Token required' });
    }

    jwt.verify(token, getJwtSecret(), (err, user) => {
      if (err) {
        return res.status(403).json({ error: 'Invalid token' });
      }

      const storedUser = db.users.get(user.userId);
      if (!storedUser) {
        return res.status(403).json({ error: 'Invalid token' });
      }

      res.json({ token: signUserToken(storedUser) });
    });
  } catch (error) {
    console.error('Error refreshing token:', error);
    res.status(500).json({ error: 'Failed to refresh token' });
  }
});

// Logout (client-side token removal)
router.post('/logout', (req, res) => {
  res.json({ message: 'Logout successful' });
});

module.exports = router;
