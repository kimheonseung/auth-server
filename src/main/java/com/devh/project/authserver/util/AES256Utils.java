package com.devh.project.authserver.util;

import org.apache.commons.lang3.StringUtils;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Value;
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

    private byte[] createSaltBytes() {
        final SecureRandom random = new SecureRandom();
        byte[] saltBytes = new byte[20];
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

    private SecretKeySpec getSecretKeySpec(String key, byte[] saltBytes) throws InvalidKeySpecException, NoSuchAlgorithmException {
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
}
