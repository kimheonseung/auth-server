import crypto from 'crypto';

const algorithm = 'aes-256-cbc';
const iv = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

const encrypt = (text) => {

  const cipher = crypto.createCipheriv(algorithm, process.env.AES_KEY, iv);
  let result = cipher.update(text, 'utf8', 'base64');
  result += cipher.final('base64');
  return result;
}

const decrypt = (text) => {
  const decipher = crypto.createDecipheriv(algorithm, process.env.AES_KEY, iv);
  let result = decipher.update(text, 'base64', 'utf8');
  result += decipher.final('utf8');
  return result;
}

export default {
  encrypt: encrypt,
  decrypt: decrypt
}