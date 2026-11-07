const express=require('express'), http=require('http'), cors=require('cors'), path=require('path'), fs=require('fs');
const bcrypt=require('bcryptjs'), jwt=require('jsonwebtoken'), multer=require('multer'), Database=require('better-sqlite3');
const {Server}=require('socket.io');
const app=express(), server=http.createServer(app), io=new Server(server,{cors:{origin:'*'}});
const PORT=process.env.PORT||3000, SECRET=process.env.JWT_SECRET||'CHANGE_ME_BEFORE_PUBLIC_DEPLOYMENT';
const db=new Database(path.join(__dirname,'..','pico.sqlite'));
const uploads=path.join(__dirname,'..','uploads'); fs.mkdirSync(uploads,{recursive:true});
app.use(cors()); app.use(express.json({limit:'2mb'})); app.use('/uploads',express.static(uploads));
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,name TEXT NOT NULL,phone TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS chats(id INTEGER PRIMARY KEY,title TEXT NOT NULL,type TEXT NOT NULL,owner_id INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS members(chat_id INTEGER NOT NULL,user_id INTEGER NOT NULL,role TEXT DEFAULT 'member',PRIMARY KEY(chat_id,user_id));
CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY,chat_id INTEGER NOT NULL,sender_id INTEGER NOT NULL,body TEXT,media_url TEXT,media_type TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
`);
const q=(sql)=>db.prepare(sql);
const tokenFor=u=>jwt.sign({id:u.id,name:u.name},SECRET,{expiresIn:'30d'});
function auth(req,res,next){try{req.user=jwt.verify((req.headers.authorization||'').replace(/^Bearer\s+/i,''),SECRET);next();}catch{res.status(401).json({error:'ابتدا وارد حساب شوید.'});}}
app.get('/api/health',(_,res)=>res.json({ok:true,app:'PICO'}));
app.post('/api/register',async(req,res)=>{
 const {name,phone,password}=req.body||{};
 const cleanPhone=String(phone||'').replace(/[\s-]/g,'');
 if(!name||!/^\\+?[0-9]{8,15}$/.test(cleanPhone)||String(password||'').length<8)return res.status(400).json({error:'نام، شماره معتبر و رمز حداقل ۸ کاراکتری وارد کنید.'});
 try{const hash=await bcrypt.hash(String(password),12);const r=q('INSERT INTO users(name,phone,password_hash) VALUES(?,?,?)').run(String(name).trim(),cleanPhone,hash);
 const user={id:r.lastInsertRowid,name:String(name).trim(),phone:cleanPhone};res.json({token:tokenFor(user),user});}
 catch{res.status(409).json({error:'این شماره قبلاً ثبت‌نام شده است.'});}
});
app.post('/api/login',async(req,res)=>{
 const phone=String(req.body?.phone||'').replace(/[\s-]/g,'');const u=q('SELECT * FROM users WHERE phone=?').get(phone);
 if(!u||!(await bcrypt.compare(String(req.body?.password||''),u.password_hash)))return res.status(401).json({error:'شماره یا رمز اشتباه است.'});
 const user={id:u.id,name:u.name,phone:u.phone};res.json({token:tokenFor(user),user});
});
app.get('/api/me',auth,(req,res)=>res.json({user:q('SELECT id,name,phone FROM users WHERE id=?').get(req.user.id)}));
app.get('/api/users',auth,(req,res)=>{const term='%'+String(req.query.q||'').slice(0,50)+'%';res.json({users:q('SELECT id,name,phone FROM users WHERE id<>? AND (name LIKE ? OR phone LIKE ?) LIMIT 30').all(req.user.id,term,term)});});
app.get('/api/chats',auth,(req,res)=>res.json({chats:q(`SELECT c.id,c.title,c.type,c.owner_id,(SELECT body FROM messages WHERE chat_id=c.id ORDER BY id DESC LIMIT 1) last_message FROM chats c JOIN members m ON m.chat_id=c.id WHERE m.user_id=? ORDER BY c.id DESC`).all(req.user.id)}));
app.post('/api/chats',auth,(req,res)=>{
 const {title,type}=req.body||{};if(!title||!['group','channel'].includes(type))return res.status(400).json({error:'عنوان و نوع گروه یا کانال لازم است.'});
 const r=q('INSERT INTO chats(title,type,owner_id) VALUES(?,?,?)').run(String(title).slice(0,80),type,req.user.id);
 q('INSERT INTO members(chat_id,user_id,role) VALUES(?,?,?)').run(r.lastInsertRowid,req.user.id,'owner');
 res.json({chat:q('SELECT * FROM chats WHERE id=?').get(r.lastInsertRowid)});
});
app.post('/api/direct',auth,(req,res)=>{
 const other=Number(req.body?.userId);if(!other||other===req.user.id||!q('SELECT id FROM users WHERE id=?').get(other))return res.status(400).json({error:'کاربر نامعتبر است.'});
 let c=q(`SELECT c.id FROM chats c JOIN members a ON a.chat_id=c.id AND a.user_id=? JOIN members b ON b.chat_id=c.id AND b.user_id=? WHERE c.type='direct' LIMIT 1`).get(req.user.id,other);
 if(!c){const tx=db.transaction(()=>{const r=q('INSERT INTO chats(title,type,owner_id) VALUES(?,?,?)').run('گفتگوی خصوصی','direct',req.user.id);q('INSERT INTO members(chat_id,user_id) VALUES(?,?)').run(r.lastInsertRowid,req.user.id);q('INSERT INTO members(chat_id,user_id) VALUES(?,?)').run(r.lastInsertRowid,other);return r.lastInsertRowid;});c={id:tx()};}
 res.json({chat:c});
});
app.get('/api/chats/:id/messages',auth,(req,res)=>{
 const id=Number(req.params.id);if(!q('SELECT 1 FROM members WHERE chat_id=? AND user_id=?').get(id,req.user.id))return res.status(403).json({error:'دسترسی ندارید.'});
 res.json({messages:q(`SELECT m.*,u.name sender_name FROM messages m JOIN users u ON u.id=m.sender_id WHERE chat_id=? ORDER BY id DESC LIMIT 100`).all(id).reverse()});
});
const storage=multer.diskStorage({destination:(_,__,cb)=>cb(null,uploads),filename:(_,f,cb)=>cb(null,Date.now()+'-'+Math.random().toString(36).slice(2)+path.extname(f.originalname).slice(0,8))});
app.post('/api/upload',auth,multer({storage,limits:{fileSize:15*1024*1024}}).single('file'),(req,res)=>{
 if(!req.file)return res.status(400).json({error:'فایل دریافت نشد.'});
 const type=req.file.mimetype.startsWith('image/')?'image':req.file.mimetype.startsWith('audio/')?'audio':'file';
 res.json({url:'/uploads/'+req.file.filename,type});
});
io.use((s,n)=>{try{s.user=jwt.verify(s.handshake.auth.token,SECRET);n();}catch{n(new Error('unauthorized'));}});
io.on('connection',s=>{
 s.on('join_chat',id=>{id=Number(id);if(q('SELECT 1 FROM members WHERE chat_id=? AND user_id=?').get(id,s.user.id))s.join('chat:'+id);});
 s.on('send_message',d=>{
  const id=Number(d.chatId);if(!q('SELECT 1 FROM members WHERE chat_id=? AND user_id=?').get(id,s.user.id))return;
  const body=String(d.body||'').slice(0,5000),url=d.mediaUrl?String(d.mediaUrl).slice(0,500):null,type=d.mediaType?String(d.mediaType).slice(0,20):null;if(!body&&!url)return;
  const r=q('INSERT INTO messages(chat_id,sender_id,body,media_url,media_type) VALUES(?,?,?,?,?)').run(id,s.user.id,body,url,type);
  const msg=q('SELECT m.*,u.name sender_name FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.id=?').get(r.lastInsertRowid);
  io.to('chat:'+id).emit('new_message',msg);
 });
});
server.listen(PORT,()=>console.log('PICO server listening on '+PORT));
