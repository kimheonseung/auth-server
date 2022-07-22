package com.devh.project.authserver.util;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
public class AES256UtilsTests {
    @InjectMocks
    AES256Utils aes256Utils;

    @BeforeEach
    public void beforeEach() {
        ReflectionTestUtils.setField(aes256Utils, "key", "devh");
    }

    @Test
    public void encrypt() throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException, InvalidKeyException, InvalidKeySpecException {
        // given
        final String givenString = "test";
        // when
        String encryptedString = aes256Utils.encrypt(givenString);
        // then
        System.out.println(encryptedString);
    }

    @Test
    public void decrypt() throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException {
        // given
        final String givenString = "+DaT3ChVfxFiO3i7g6FPHFxlenMROTVUb+fJSh9/XGcFVaivRC+v5lJcq2ps2nK0V1lpEg==";
        // when
        String decryptedString = aes256Utils.decrypt(givenString);
        // then
        assertEquals(decryptedString, "test");
    }
}
