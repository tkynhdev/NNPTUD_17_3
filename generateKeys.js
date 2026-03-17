const fs = require('fs');
const crypto = require('crypto');

// Tạo RSA key pair 2048 bytes
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
    },
    privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
    }
});

// Lưu vào file
fs.writeFileSync('private.key', privateKey);
fs.writeFileSync('public.key', publicKey);

console.log('✓ Tạo key pair thành công!');
console.log('private.key - Private key (dùng để ký token)');
console.log('public.key - Public key (dùng để xác minh token)');
