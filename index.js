require('dotenv').config();
const { Client } = require('pg');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
app.use(cors());
const PORT = process.env.PORT || 3000;

app.use(express.json()); // ใช้ JSON body parser

const con = new Client({
    host: 'localhost',
    user: 'postgres',
    port: 5432,
    password: process.env.DB_PASSWORD, // ใช้ตัวแปรจาก .env
    database: 'application_access_control'
});

// เชื่อมต่อกับฐานข้อมูล
con.connect()
    .then(() => {
        console.log('Connected to database');
    })
    .catch(err => {
        console.error('Database connection error', err.stack);
    });

const generateToken = (user)=>{
    const payload = { id: user.id, email: user.email }; // กำหนด payload ที่ต้องการ
    const secret = process.env.JWT_SECRET; // คีย์ลับที่ใช้ในการสร้าง token
    const options = { expiresIn: '1h' }; // ระบุว่า token มีอายุการใช้งาน 1 ชั่วโมง
  
    return jwt.sign(payload, secret, options);
}

// Middleware สำหรับตรวจสอบ JWT token
const authenticateToken = (req, res, next)=> {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // แยกคำว่า 'Bearer' ออก
  
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
  
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
          if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ message: 'Token expired' }); // 401: Unauthorized เมื่อ token หมดอายุ
          }
          return res.status(403).json({ message: 'Invalid token' }); // 403: Forbidden สำหรับ token ที่ไม่ถูกต้อง
        }
        
        req.user = user; // เก็บข้อมูลผู้ใช้ที่ถอดรหัสได้ใน req.user
        next(); // ดำเนินการต่อ
    });
}

// API สำหรับการสมัครสมาชิก
app.post('/api/signup', async (req, res) => {
    let { email, password } = req.body;

    // ตรวจสอบว่า email และ password ถูกส่งมา
    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required' });
    }

    // แปลง email เป็นพิมพ์เล็ก
    email = email.toLowerCase();

    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{7,}$/;
    if (!passwordRegex.test(password)) {
        return res.status(400).json({ message: 'Password must be at least 7 characters long and include at least one uppercase letter, one lowercase letter, and one number.' });
    }

    try {
        // ตรวจสอบว่า email ซ้ำหรือไม่
        const emailCheck = await con.query('SELECT * FROM users WHERE email = $1', [email]);
        if (emailCheck.rows.length > 0) {
            return res.status(400).json({ message: 'Email already exists' });
        }

        // แฮชรหัสผ่าน
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // บันทึกข้อมูลผู้ใช้ลงในฐานข้อมูล
        const result = await con.query(
            'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING *',
            [email, hashedPassword]
        );

        // สร้าง JWT token
        const token = generateToken(result.rows[0]);
        
        // ส่งข้อมูลผู้ใช้ที่ถูกสร้างขึ้น
        res.status(201).json({
            message: 'User registered successfully',
            user: {
                id: result.rows[0].id,
                email: result.rows[0].email,
                role: result.rows[0].role
            },
            token: token
        });
    } catch (error) {
        console.error('Error inserting user:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// API สำหรับการเข้าสู่ระบบ
app.post('/api/signin', async (req, res) => {
    let { email, password } = req.body;

    // ตรวจสอบว่า email และ password ถูกส่งมา
    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required' });
    }

    // แปลง email เป็นพิมพ์เล็ก
    email = email.toLowerCase();

    try {
        // ค้นหาผู้ใช้จากอีเมล
        const userResult = await con.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = userResult.rows[0];

        if (!user) {
            // บันทึกการเข้าสู่ระบบไม่สำเร็จ
            await con.query(
                'INSERT INTO login_logs (user_email, success, message) VALUES ($1, $2, $3)',
                [email, false, 'Email or password is incorrect.']
            );

            return res.status(400).json({message: 'Email or password is incorrect.'});
        }

        // ตรวจสอบว่าบัญชีถูกล็อคหรือไม่
        if (user.is_locked) {
            const lockDuration = 1 * 60 * 1000; // 1 นาที
            const currentTime = Date.now();
            const lockTime = new Date(user.lock_time).getTime();

            if (currentTime - lockTime < lockDuration) {
                // บันทึกการเข้าสู่ระบบไม่สำเร็จ
                await con.query(
                    'INSERT INTO login_logs (user_email, success, message) VALUES ($1, $2, $3)',
                    [email, false, 'Account is locked']
                );

                return res.status(403).json({message: 'Account is locked. Please try again later.'});
            } else {
                // ปลดล็อคบัญชีหลังจาก 1 นาที
                await con.query('UPDATE users SET is_locked = FALSE, login_attempts = 0, lock_time = NULL WHERE email = $1', [email]);
            }
        }

        // ตรวจสอบรหัสผ่าน
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            // เพิ่มจำนวนครั้งที่พยายามเข้าสู่ระบบไม่สำเร็จ
            await con.query('UPDATE users SET login_attempts = login_attempts + 1 WHERE email = $1', [email]);

            // บันทึกการเข้าสู่ระบบไม่สำเร็จ
            await con.query(
                'INSERT INTO login_logs (user_email, success, message) VALUES ($1, $2, $3)',
                [email, false, 'Email or password is incorrect.']
            );

            // ตรวจสอบจำนวนครั้งที่พยายามเข้าสู่ระบบ
            if (user.login_attempts + 1 >= 5) {
                const lockTime = new Date(); // เวลาปัจจุบัน
                await con.query('UPDATE users SET is_locked = TRUE, lock_time = $1 WHERE email = $2', [lockTime, email]);
                return res.status(403).json({message: 'Account locked due to too many failed login attempts.'})
            }

            return res.status(400).json({message: 'Email or password is incorrect.'})
        }

        // รีเซ็ตจำนวนครั้งที่พยายามเข้าสู่ระบบเมื่อเข้าสู่ระบบสำเร็จ
        await con.query('UPDATE users SET login_attempts = 0 WHERE email = $1', [email]);

        // ตรวจสอบวันที่ที่ผู้ใช้เปลี่ยนรหัสผ่านครั้งล่าสุด
        const now = new Date();
        const passwordLastChanged = new Date(user.password_last_changed);
        const daysSinceLastChange = Math.floor((now - passwordLastChanged) / (1000 * 60 * 60 * 24));

        // ถ้าเกิน 90 วันให้ส่ง response กลับเพื่อบังคับให้เปลี่ยนรหัสผ่าน
        if (daysSinceLastChange >= 90) {
            return res.status(403).json({message: 'You need to change your password. It has been more than 90 days since the last change.'})
        }

        // บันทึกการเข้าสู่ระบบสำเร็จ
        await con.query(
            'INSERT INTO login_logs (user_email, success, message) VALUES ($1, $2, $3)',
            [email, true, 'Login successful']
        );

        // สร้าง JWT token
        const token = generateToken(user);

        // ส่ง JWT หรือข้อมูลอื่น ๆ ที่ต้องการ
        res.status(200).json({message: 'Login successful.', token: token, user: user});
    } catch (error) {
        //console.error(error);
        res.status(500).json({message: 'Error during login.'})
    }
});


app.post('/api/request-password-reset', async (req, res) => {
    const { email } = req.body;
    const token = crypto.randomBytes(20).toString('hex'); // สร้าง token
    const expiration = new Date(Date.now() + 3600000).toISOString(); // ตั้งเวลาใช้งาน token 1 ชั่วโมงในรูปแบบ ISO

    try {
        // บันทึก token ลงในฐานข้อมูล (พร้อมวันหมดอายุ)
        await con.query('UPDATE users SET reset_token = $1, reset_token_expiration = $2 WHERE email = $3', [token, expiration, email]);
        
        // ส่งอีเมล
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.SEND_EMAIL,
                pass: process.env.SEND_EMAIL_PASSWORD
            },
            tls: {
                rejectUnauthorized: false // อนุญาตใบรับรอง self-signed
            }
        });

        const resetLink = `http://localhost:3001/reset-password/${token}`;
        await transporter.sendMail({
            to: email,
            subject: 'Password Reset',
            text: `Click the following link to reset your password: ${resetLink}`
        });

        res.status(200).json({message: 'Password reset link sent to your email.'})
    } catch (error) {
        console.error(error);
        res.status(500).json({message: 'Error while sending reset link.'})
    }
});

app.post('/api/reset-password', async (req, res) => {
    const { newPassword, token } = req.body;

    try {
        const expiration = new Date(Date.now()).toISOString();

        // ตรวจสอบ token และความถูกต้องของมัน
        const result = await con.query('SELECT * FROM users WHERE reset_token = $1 AND reset_token_expiration > $2', [token, expiration]);

        if (result.rows.length === 0) {
            return res.status(400).json({message: 'Invalid or expired token.'})
        }

        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{7,}$/;
        if (!passwordRegex.test(newPassword)) {
            return res.status(400).json({ message: 'Password must be at least 7 characters long and include at least one uppercase letter, one lowercase letter, and one number.' });
        }

        // แฮชรหัสผ่านใหม่
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // อัปเดตรหัสผ่านในฐานข้อมูลและลบ token
        await con.query('UPDATE users SET password_hash = $1, password_last_changed = NOW(), reset_token = NULL, reset_token_expiration = NULL WHERE reset_token = $2', [hashedPassword, token]);

        res.status(200).json({message: 'Password has been reset successfully.'})
    } catch (error) {
        console.error(error);
        res.status(500).json({message: 'Error resetting password.'})
    }
});

// API สำหรับการเปลี่ยนรหัสผ่าน
app.post('/api/change-password', async (req, res) => {
    let { email, currentPassword, newPassword } = req.body;

    // ตรวจสอบว่า email currentPassword และ newPassword ถูกส่งมา
    if (!email || !currentPassword || !newPassword) {
        return res.status(400).json({ message: 'Email, Password and new password are required' });
    }

    // แปลง email เป็นพิมพ์เล็ก
    email = email.toLowerCase();

    try {

        // ค้นหาผู้ใช้จากอีเมล
        const userResult = await con.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = userResult.rows[0];

        if (!user) {
            // บันทึกการเข้าสู่ระบบไม่สำเร็จ
            await con.query(
                'INSERT INTO login_logs (user_email, success, message) VALUES ($1, $2, $3)',
                [email, false, 'Email or password is incorrect.']
            );

            return res.status(400).json({message: 'Email or password is incorrect.'});
        }

        // ตรวจสอบว่าบัญชีถูกล็อคหรือไม่
        if (user.is_locked) {
            const lockDuration = 1 * 60 * 1000; // 1 นาที
            const currentTime = Date.now();
            const lockTime = new Date(user.lock_time).getTime();

            if (currentTime - lockTime < lockDuration) {
                // บันทึกการเข้าสู่ระบบไม่สำเร็จ
                await con.query(
                    'INSERT INTO login_logs (user_email, success, message) VALUES ($1, $2, $3)',
                    [email, false, 'Account is locked']
                );

                return res.status(403).json({message: 'Account is locked. Please try again later.'});
            } else {
                // ปลดล็อคบัญชีหลังจาก 1 นาที
                await con.query('UPDATE users SET is_locked = FALSE, login_attempts = 0, lock_time = NULL WHERE email = $1', [email]);
            }
        }

        // ตรวจสอบรหัสผ่าน
        const isMatch = await bcrypt.compare(currentPassword, user.password_hash);
        if (!isMatch) {
            // เพิ่มจำนวนครั้งที่พยายามเข้าสู่ระบบไม่สำเร็จ
            await con.query('UPDATE users SET login_attempts = login_attempts + 1 WHERE email = $1', [email]);

            // บันทึกการเข้าสู่ระบบไม่สำเร็จ
            await con.query(
                'INSERT INTO login_logs (user_email, success, message) VALUES ($1, $2, $3)',
                [email, false, 'Email or password is incorrect.']
            );

            // ตรวจสอบจำนวนครั้งที่พยายามเข้าสู่ระบบ
            if (user.login_attempts + 1 >= 5) {
                const lockTime = new Date(); // เวลาปัจจุบัน
                await con.query('UPDATE users SET is_locked = TRUE, lock_time = $1 WHERE email = $2', [lockTime, email]);
                return res.status(403).json({message: 'Account locked due to too many failed login attempts.'})
            }

            return res.status(400).json({message: 'Email or password is incorrect.'})
        }

        // รีเซ็ตจำนวนครั้งที่พยายามเข้าสู่ระบบเมื่อเข้าสู่ระบบสำเร็จ
        await con.query('UPDATE users SET login_attempts = 0 WHERE email = $1', [email]);

        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{7,}$/;
        if (!passwordRegex.test(newPassword)) {
            return res.status(400).json({ message: 'Password must be at least 7 characters long and include at least one uppercase letter, one lowercase letter, and one number.' });
        }

        // แฮชรหัสผ่านใหม่
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

        // อัปเดตรหัสผ่านใหม่และวันที่ที่เปลี่ยนรหัสผ่านในฐานข้อมูล
        await con.query(
            'UPDATE users SET password_hash = $1, password_last_changed = NOW() WHERE email = $2',
            [hashedPassword, email]
        );

        // บันทึกการเปลี่ยนรหัสผ่านสำเร็จ
        await con.query(
            'INSERT INTO login_logs (user_email, success, message) VALUES ($1, $2, $3)',
            [email, true, 'Password has been changed successfully.']
        );


        res.status(200).json({ message: 'Password has been changed successfully.'});
    } catch (error) {
        console.error('Error changing password:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/logs', authenticateToken, async (req, res) => {
    const result = await con.query('SELECT * FROM login_logs');
    try{
        res.status(200).json(result.rows);
    } catch (error){
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/verify-jwt-token', authenticateToken, async (req, res) => {
    return res.status(200).json({message: 'Authentication successful'});
});


// เริ่มต้นเซิร์ฟเวอร์
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
