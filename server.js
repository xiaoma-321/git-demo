// server.js - 简单后端：调用本地 PQC.exe 来完成 genkey/encrypt/decrypt
const express = require('express');
const multer = require('multer');
const { execFile } = require('child_process');
const path = require('path');
const fs = require('fs-extra');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// 项目根目录（server.js 所在目录）
const ROOT = __dirname;
const WEB = path.join(ROOT, 'web');
const TMP = path.join(ROOT, 'tmp');
fs.ensureDirSync(TMP);

// 可执行程序路径（在工程根目录下）
const BIN_PATH = path.join(ROOT, 'PQC.exe'); // 如果是 oqs_emr.exe，请改名这里

// 静态页面托管
app.use('/', express.static(WEB));

// 上传配置
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, TMP),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

// --------- API: 生成密钥对（无上传） ----------
app.post('/api/genkey', (req, res) => {
  const id = uuidv4();
  const pubPath = path.join(TMP, `${id}.pub`);
  const secPath = path.join(TMP, `${id}.sec`);

  execFile(BIN_PATH, ['genkey', pubPath, secPath], { cwd: ROOT }, (err, stdout, stderr) => {
    if (err) {
      console.error('genkey err:', err, stderr);
      return res.status(500).json({ success: false, error: stderr || err.message });
    }
    try {
      const pubBuf = fs.readFileSync(pubPath);
      const secBuf = fs.readFileSync(secPath);
      res.json({
        success: true,
        pubBase64: pubBuf.toString('base64'),
        secBase64: secBuf.toString('base64'),
        pubFile: path.basename(pubPath),
        secFile: path.basename(secPath)
      });
    } catch (e) {
      res.status(500).json({ success: false, error: e.message });
    }
  });
});

// --------- API: 加密（上传公钥 + 明文文件） ----------
app.post('/api/encrypt', upload.fields([{ name: 'pubkey', maxCount: 1 }, { name: 'file', maxCount: 1 }]), (req, res) => {
  if (!req.files || !req.files['pubkey'] || !req.files['file']) {
    return res.status(400).json({ success: false, error: '需要上传 pubkey 和 file' });
  }
  const pub = req.files['pubkey'][0].path;
  const file = req.files['file'][0].path;
  const outBundle = path.join(TMP, uuidv4() + '.bundle');

  execFile(BIN_PATH, ['encrypt', pub, file, outBundle], { cwd: ROOT }, (err, stdout, stderr) => {
    if (err) {
      console.error('encrypt err:', err, stderr);
      return res.status(500).json({ success: false, error: stderr || err.message });
    }
    // 直接返回文件供前端下载
    res.download(outBundle, path.basename(outBundle), (downloadErr) => {
      if (downloadErr) console.error('download err', downloadErr);
    });
  });
});

// --------- API: 解密（上传 secret key + bundle） ----------

app.post('/api/decrypt', upload.fields([
  { name: 'seckey', maxCount: 1 },
  { name: 'bundle', maxCount: 1 }
]), (req, res) => {
  if (!req.files || !req.files['seckey'] || !req.files['bundle']) {
    return res.status(400).json({ success: false, error: '需要上传 seckey 和 bundle' });
  }

  const seckey = req.files['seckey'][0].path;
  const bundle = req.files['bundle'][0].path;

  const outPlainArg = 'auto'; // 让 PQC.exe 自动恢复原始文件名

  execFile(BIN_PATH, ['decrypt', seckey, bundle, outPlainArg], { cwd: ROOT }, (err, stdout, stderr) => {
    if (err) {
      console.error('decrypt err:', err, stderr);
      return res.status(500).json({ success: false, error: stderr || err.message });
    }

    // 解析 stdout 中的 "Decrypted -> <full-path>"
    const m = stdout.match(/Decrypted -> (.+)\s*/);
    let decryptedFullPath = null;
    if (m && m[1]) {
      decryptedFullPath = m[1].trim();
    } else {
      decryptedFullPath = path.join(path.dirname(bundle), 'plain_out');
    }

    // 返回文件给前端
    res.download(decryptedFullPath, path.basename(decryptedFullPath), (downloadErr) => {
      if (downloadErr) console.error('download err', downloadErr);
      // 可以在这里清理临时文件
    });
  });
});


// 小工具：列出 tmp 文件（可选，调试用）
app.get('/api/tmp', (req, res) => {
  res.json({ files: fs.readdirSync(TMP) });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}/`);
});
