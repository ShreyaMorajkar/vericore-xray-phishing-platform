const { spawn } = require('child_process');
const path = require('path');

console.log('======================================================================');
console.log('  VERICORE // X-RAY — Multi-Layer Phishing Dissection Platform');
console.log('  Starting Backend API (Port 5000) + Next.js Frontend (Port 3000)...');
console.log('======================================================================');

const isWin = process.platform === 'win32';
const npmCmd = isWin ? 'npm.cmd' : 'npm';

const backend = spawn(npmCmd, ['run', 'dev'], {
  cwd: path.join(__dirname, 'backend'),
  stdio: 'inherit',
  shell: true
});

const frontend = spawn(npmCmd, ['run', 'dev'], {
  cwd: path.join(__dirname, 'frontend'),
  stdio: 'inherit',
  shell: true
});

process.on('SIGINT', () => {
  backend.kill();
  frontend.kill();
  process.exit();
});
