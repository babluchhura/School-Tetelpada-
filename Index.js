require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_key_999';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/school_management';

// --- DATABASE CONNECTION ---
mongoose.connect(MONGODB_URI).then(() => {
    console.log('Connected to MongoDB');
    initAdmin();
}).catch(err => console.log('MongoDB Connection Error:', err));

// --- MONGODB SCHEMAS & MODELS ---
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'staff', 'student'], required: true },
    name: { type: String, required: true },
    email: String,
    className: String, // Assigned class/section
    contact: String
});
const User = mongoose.model('User', UserSchema);

const AttendanceSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    date: { type: String, required: true }, // YYYY-MM-DD
    status: { type: String, enum: ['Present', 'Absent', 'Late', 'Leave'], required: true }
});
const Attendance = mongoose.model('Attendance', AttendanceSchema);

const ResultSchema = new mongoose.Schema({
    studentId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    examName: String,
    subject: String,
    marksObtained: Number,
    totalMarks: Number,
    grade: String
});
const Result = mongoose.model('Result', ResultSchema);

const LeaveSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    startDate: String,
    endDate: String,
    reason: String,
    status: { type: String, enum: ['Pending', 'Approved', 'Rejected'], default: 'Pending' }
});
const Leave = mongoose.model('Leave', LeaveSchema);

const NotificationSchema = new mongoose.Schema({
    message: String,
    targetRole: { type: String, enum: ['all', 'staff', 'student'] },
    date: { type: Date, default: Date.now },
    author: String
});
const Notification = mongoose.model('Notification', NotificationSchema);

// --- INITIALIZE DEFAULT ADMIN ---
async function initAdmin() {
    if (await User.countDocuments({ role: 'admin' }) === 0) {
        const hash = await bcrypt.hash('admin123', 10);
        await User.create({ username: 'admin', password: hash, role: 'admin', name: 'System Administrator' });
        console.log('Default Admin Account Created (admin / admin123)');
    }
}

// --- MIDDLEWARES ---
const auth = (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access Denied. No token provided.' });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) { res.status(400).json({ error: 'Invalid Token.' }); }
};

const requireRole = (roles) => (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Forbidden Access' });
    next();
};

// --- API ENDPOINTS ---

// AUTHENTICATION
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: 'Invalid Credentials' });
    const validPass = await bcrypt.compare(password, user.password);
    if (!validPass) return res.status(400).json({ error: 'Invalid Credentials' });
    
    const token = jwt.sign({ id: user._id, role: user.role, name: user.name, className: user.className }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: { id: user._id, name: user.name, role: user.role, className: user.className } });
});

app.post('/api/change-password', auth, async (req, res) => {
    const { newPassword } = req.body;
    const hash = await bcrypt.hash(newPassword, 10);
    await User.findByIdAndUpdate(req.user.id, { password: hash });
    res.json({ message: 'Password updated successfully' });
});

// DASHBOARD STATS & CHART DATA
app.get('/api/stats', auth, async (req, res) => {
    try {
        let stats = {};
        if (req.user.role === 'admin') {
            stats.students = await User.countDocuments({ role: 'student' });
            stats.staff = await User.countDocuments({ role: 'staff' });
            stats.pendingLeaves = await Leave.countDocuments({ status: 'Pending' });
            
            const attendanceAgg = await Attendance.aggregate([{ $group: { _id: '$status', count: { $sum: 1 } } }]);
            stats.attendanceChart = { labels: [], data: [] };
            attendanceAgg.forEach(a => { stats.attendanceChart.labels.push(a._id); stats.attendanceChart.data.push(a.count); });
        } else if (req.user.role === 'student') {
            const results = await Result.find({ studentId: req.user.id });
            stats.performanceChart = { labels: results.map(r => r.subject), data: results.map(r => r.marksObtained) };
            const myAtt = await Attendance.find({ userId: req.user.id });
            const present = myAtt.filter(a => a.status === 'Present').length;
            stats.attendancePercentage = myAtt.length ? ((present / myAtt.length) * 100).toFixed(1) + '%' : 'N/A';
        }
        res.json(stats);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// USER MANAGEMENT (Admin/Staff)
app.get('/api/users/:role', auth, async (req, res) => {
    let query = { role: req.params.role };
    if (req.user.role === 'staff' && req.params.role === 'student') query.className = req.user.className; 
    const users = await User.find(query).select('-password');
    res.json(users);
});

app.post('/api/users', auth, requireRole(['admin']), async (req, res) => {
    const { username, password, role, name, email, className, contact } = req.body;
    try {
        const hash = await bcrypt.hash(password, 10);
        await User.create({ username, password: hash, role, name, email, className, contact });
        res.json({ message: 'User added successfully' });
    } catch (err) { res.status(400).json({ error: 'Username might exist or missing fields' }); }
});

app.delete('/api/users/:id', auth, requireRole(['admin']), async (req, res) => {
    await User.findByIdAndDelete(req.params.id);
    res.json({ message: 'User deleted' });
});

// ATTENDANCE
app.get('/api/attendance', auth, async (req, res) => {
    let filter = {};
    if (req.user.role === 'student') filter.userId = req.user.id;
    const records = await Attendance.find(filter).populate('userId', 'name className role').sort({ date: -1 });
    res.json(records);
});

app.post('/api/attendance', auth, requireRole(['admin', 'staff']), async (req, res) => {
    const { userId, date, status } = req.body;
    await Attendance.findOneAndUpdate({ userId, date }, { status }, { upsert: true, new: true });
    res.json({ message: 'Attendance marked' });
});

// RESULTS
app.get('/api/results', auth, async (req, res) => {
    let filter = {};
    if (req.user.role === 'student') filter.studentId = req.user.id;
    const results = await Result.find(filter).populate('studentId', 'name className').sort({ examName: 1 });
    res.json(results);
});

app.post('/api/results', auth, requireRole(['admin', 'staff']), async (req, res) => {
    const { studentId, examName, subject, marksObtained, totalMarks } = req.body;
    const percentage = (marksObtained / totalMarks) * 100;
    const grade = percentage >= 90 ? 'A+' : percentage >= 80 ? 'A' : percentage >= 70 ? 'B' : percentage >= 60 ? 'C' : percentage >= 50 ? 'D' : 'F';
    await Result.create({ studentId, examName, subject, marksObtained, totalMarks, grade });
    res.json({ message: 'Result added successfully' });
});

// LEAVES
app.get('/api/leaves', auth, async (req, res) => {
    let filter = {};
    if (req.user.role !== 'admin') filter.userId = req.user.id;
    const leaves = await Leave.find(filter).populate('userId', 'name role').sort({ _id: -1 });
    res.json(leaves);
});

app.post('/api/leaves', auth, async (req, res) => {
    const { startDate, endDate, reason } = req.body;
    await Leave.create({ userId: req.user.id, startDate, endDate, reason });
    res.json({ message: 'Leave application submitted' });
});

app.put('/api/leaves/:id', auth, requireRole(['admin']), async (req, res) => {
    await Leave.findByIdAndUpdate(req.params.id, { status: req.body.status });
    res.json({ message: `Leave ${req.body.status}` });
});

// NOTIFICATIONS
app.get('/api/notifications', auth, async (req, res) => {
    const query = req.user.role === 'admin' ? {} : { targetRole: { $in: ['all', req.user.role] } };
    const notes = await Notification.find(query).sort({ date: -1 });
    res.json(notes);
});

app.post('/api/notifications', auth, requireRole(['admin', 'staff']), async (req, res) => {
    await Notification.create({ ...req.body, author: req.user.name });
    res.json({ message: 'Notification sent' });
});

// --- SERVE FRONTEND ---
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'Student Management System.html'));
});

if (require.main === module) {
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}
module.exports = app;
