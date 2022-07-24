package com.devh.project.authserver.util;

import org.apache.commons.lang3.StringUtils;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.stereotype.Component;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

/**
 * <pre>
 * Description :
 *     AES256 암/복호화 유틸
 * ===============================================
 * Member fields :
 *
 * ===============================================
 *
 * Author : HeonSeung Kim
 * Date   : 2022. 6. 1.
 * </pre>
 */
@Component
public class AES256Utils {
    @Value("${aes.key}")
    private String key;

    public String encrypt(String s) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidParameterSpecException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {

        if (StringUtils.isNotEmpty(s)) {

            final byte[] saltBytes = createSaltBytes();

            final SecretKeySpec secret = getSecretKeySpec(saltBytes);

            final Cipher cipher = getCipher();
            cipher.init(Cipher.ENCRYPT_MODE, secret);
            final AlgorithmParameters params = cipher.getParameters();

            byte[] encryptedTextBytes = cipher.doFinal(s.getBytes(StandardCharsets.UTF_8));

            /* Initial Vector(1단계 암호화 블록용) */
            byte[] ivBytes = params.getParameterSpec(IvParameterSpec.class).getIV();

            /* salt + Initial Vector + 암호문 결합 후 Base64인코딩 */
            byte[] buffer = new byte[saltBytes.length + ivBytes.length + encryptedTextBytes.length];
            System.arraycopy(saltBytes, 0, buffer, 0, saltBytes.length);
            System.arraycopy(ivBytes, 0, buffer, saltBytes.length, ivBytes.length);
            System.arraycopy(encryptedTextBytes, 0, buffer, saltBytes.length + ivBytes.length, encryptedTextBytes.length);

            return Base64.encodeBase64String(buffer);
        } else {
            return null;
        }
    }

    public String decrypt(String s) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {

        if (StringUtils.isNotEmpty(s)) {
            final Cipher cipher = getCipher();

            final ByteBuffer buffer = ByteBuffer.wrap(Base64.decodeBase64(s));

            final byte[] saltBytes = createSaltBytes();
            buffer.get(saltBytes, 0, saltBytes.length);

            final byte[] ivBytes = new byte[cipher.getBlockSize()];
            buffer.get(ivBytes, 0, ivBytes.length);

            final byte[] encryptedTextBytes = new byte[buffer.capacity() - saltBytes.length - ivBytes.length];
            buffer.get(encryptedTextBytes);

            final SecretKeySpec secret = getSecretKeySpec(saltBytes);

            cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(ivBytes));

            byte[] decryptedTextBytes = cipher.doFinal(encryptedTextBytes);
            return new String(decryptedTextBytes);
        } else {
            return null;
        }
    }

    public String decryptByCryptoJS(String s) throws Exception {
        if (StringUtils.isNotEmpty(s)) {
            final Cipher cipher = getCipher();

            final String strSalt = s.substring(0, 32);
            final String strIv = s.substring(32, 64);
            final String strString = s.substring(64);

            final byte[] saltBytes = Hex.decode(strSalt);
            final byte[] ivBytes = Hex.decode(strIv);
            final byte[] stringBytes = Base64.decodeBase64(strString);

            final SecretKeySpec secret = getSecretKeySpec(saltBytes);
            cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(ivBytes));
            byte[] decryptedTextBytes = cipher.doFinal(stringBytes);
            return new String(decryptedTextBytes);
        } else {
            return null;
        }
    }

    private byte[] createSaltBytes() {
        final SecureRandom random = new SecureRandom();
        byte[] saltBytes = new byte[16];
        random.nextBytes(saltBytes);
        return saltBytes;
    }

    private SecretKeySpec getSecretKeySpec(byte[] saltBytes) throws InvalidKeySpecException, NoSuchAlgorithmException {
        /* Password-Based Key Derivation function */
        final SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        /* 1000번 해시하여 256 bit 키 spec 생성*/
        final PBEKeySpec spec = new PBEKeySpec(key.toCharArray(), saltBytes, 1000, 256);
        /* 비밀키 생성 */
        final SecretKey secretKey = factory.generateSecret(spec);
        return new SecretKeySpec(secretKey.getEncoded(), "AES");
    }

    private Cipher getCipher() throws NoSuchAlgorithmException, NoSuchPaddingException {
        return Cipher.getInstance("AES/CBC/PKCS5Padding");    /* 알고리즘/모드/패딩 */
    }

//    public String decrypt(String ciphertext, String passphrase) {
//        try {
//            final int keySize = 256;
//            final int ivSize = 128;
//
//            // 텍스트를 BASE64 형식으로 디코드 한다.
//            byte[] ctBytes = Base64.decodeBase64(ciphertext.getBytes("UTF-8"));
//
//            // 솔트를 구한다. (생략된 8비트는 Salted__ 시작되는 문자열이다.)
//            byte[] saltBytes = Arrays.copyOfRange(ctBytes, 8, 16);
//
//
//            // 암호화된 테스트를 구한다.( 솔트값 이후가 암호화된 텍스트 값이다.)
//            byte[] ciphertextBytes = Arrays.copyOfRange(ctBytes, 16, ctBytes.length);
//
//            // 비밀번호와 솔트에서 키와 IV값을 가져온다.
//            byte[] key = new byte[keySize / 8];
//            byte[] iv = new byte[ivSize / 8];
//            EvpKDF(passphrase.getBytes("UTF-8"), keySize, ivSize, saltBytes, key, iv);
//
//            // 복호화
//            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
//            byte[] recoveredPlaintextBytes = cipher.doFinal(ciphertextBytes);
//
//            return new String(recoveredPlaintextBytes);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//
//        return null;
//    }
//
//    private static byte[] EvpKDF(byte[] password, int keySize, int ivSize, byte[] salt, byte[] resultKey, byte[] resultIv) throws NoSuchAlgorithmException {
//        return EvpKDF(password, keySize, ivSize, salt, 1, "MD5", resultKey, resultIv);
//    }
//
//    private static byte[] EvpKDF(byte[] password, int keySize, int ivSize, byte[] salt, int iterations, String hashAlgorithm, byte[] resultKey, byte[] resultIv) throws NoSuchAlgorithmException {
//        keySize = keySize / 32;
//        ivSize = ivSize / 32;
//        int targetKeySize = keySize + ivSize;
//        byte[] derivedBytes = new byte[targetKeySize * 4];
//        int numberOfDerivedWords = 0;
//        byte[] block = null;
//        MessageDigest hasher = MessageDigest.getInstance(hashAlgorithm);
//        while (numberOfDerivedWords < targetKeySize) {
//            if (block != null) {
//                hasher.update(block);
//            }
//            hasher.update(password);
//            // Salting
//            block = hasher.digest(salt);
//            hasher.reset();
//            // Iterations : 키 스트레칭(key stretching)
//            for (int i = 1; i < iterations; i++) {
//                block = hasher.digest(block);
//                hasher.reset();
//            }
//            System.arraycopy(block, 0, derivedBytes, numberOfDerivedWords * 4, Math.min(block.length, (targetKeySize - numberOfDerivedWords) * 4));
//            numberOfDerivedWords += block.length / 4;
//        }
//        System.arraycopy(derivedBytes, 0, resultKey, 0, keySize * 4);
//        System.arraycopy(derivedBytes, keySize * 4, resultIv, 0, ivSize * 4);
//        return derivedBytes; // key + iv
//    }
}
