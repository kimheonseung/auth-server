const aes256Service = () => {
  const converter = {
    wordToByteArray : (word, length) => {
      let ba = [];
      const xFF = 0xFF;
      if (length > 0)
        ba.push(word >>> 24);
      if (length > 1)
        ba.push((word >>> 16) & xFF);
      if (length > 2)
        ba.push((word >>> 8) & xFF);
      if (length > 3)
        ba.push(word & xFF);

      return ba;
    },
    wordArrayToByteArray : (wordArray, length) => {
      if (wordArray.hasOwnProperty("sigBytes") && wordArray.hasOwnProperty("words")) {
        length = wordArray.sigBytes;
        wordArray = wordArray.words;
      }

      let result = [];
      let bytes;
      let i = 0;
      while (length > 0) {
        bytes = converter.wordToByteArray(wordArray[i], Math.min(4, length));
        length -= bytes.length;
        result.push(bytes);
        i++;
      }
      return [].concat.apply([], result);
    },
    byteArrayToWordArray : (ba) => {
      let wa = [];
      for (let i = 0; i < ba.length; i++) {
        wa[(i / 4) | 0] |= ba[i] << (24 - 8 * i);
      }
      return CryptoJS.lib.WordArray.create(wa, ba.length);
    }
  }

  const encrypt = (str, type) => {
    const salt = CryptoJS.lib.WordArray.random(128 / 8);
    const iv = CryptoJS.lib.WordArray.random(128 / 8);
    const key256Bits = CryptoJS.PBKDF2(key, salt, {
      keySize: 256 / 32,
      iterations: 1000
    });
    const encrypted = CryptoJS.AES.encrypt(CryptoJS.enc.Utf8.parse("test"), key256Bits, {
      iv: iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7
    });

    let encryptedString;
    if(type === undefined || type === 'server') {
      let result = [];
      converter.wordArrayToByteArray(salt).forEach(w => result.push(w));
      converter.wordArrayToByteArray(iv).forEach(w => result.push(w));
      converter.wordArrayToByteArray(encrypted.ciphertext).forEach(w => result.push(w));
      encryptedString = CryptoJS.enc.Base64.stringify(converter.byteArrayToWordArray(result));
    } else {
      encryptedString = salt.toString(CryptoJS.enc.Hex) + iv.toString(CryptoJS.enc.Hex) + CryptoJS.enc.Base64.stringify(encrypted.ciphertext);
    }

    return encryptedString;
  }

  return {
    encrypt: encrypt
  }
}