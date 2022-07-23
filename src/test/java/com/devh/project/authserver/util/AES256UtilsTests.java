package com.devh.project.authserver.util;

import org.apache.tomcat.util.codec.binary.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
public class AES256UtilsTests {
    @InjectMocks
    AES256Utils aes256Utils;

    @BeforeEach
    public void beforeEach() {
        ReflectionTestUtils.setField(aes256Utils, "key", "devh0000000000000000000000000000");
    }

    @Test
    public void encrypt() throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException, InvalidKeyException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        // given
        final String givenString = "test";
        // when
        String encryptedString = aes256Utils.encrypt(givenString);
        // then
        System.out.println(encryptedString);
    }

    @Test
    public void decrypt() throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException, InvalidParameterSpecException {
        // given

//        final String givenString = "BhnLom3zYsvxAvWIdXvPAmUzstlJYwECNk0OxjXfZZOWvdeJOff7MG7yzlTE7I5kx5kTGQ==";
//        final String givenString = "YdQDK4TdRNluYKAhiUx0l3S75mfTR7NnKcK2D8lWMXs=";
        final String givenString = "LVhFgWbvue4wxFfRHl2Q2IZva7wq8x0zVoEZ5LCoPrb4rqjklyOuf00v/nVjohZ+";
        // when
        String decryptedString = aes256Utils.decrypt(givenString);

        // then
        assertEquals(decryptedString, "test");
    }

    @Test
    public void decryptByCryptoJS() throws Exception {
        final String givenString = "21ac82b912eaa161f7a38331409f2760cb82b51f9d3285151fe158ef0dace117LuvDo/pdkFLGF3LvnmCyjg==";
        String a = aes256Utils.decryptByCryptoJS(givenString);
        System.out.println(a);
    }

    @Test
    public void testSalt() throws UnsupportedEncodingException {
        final SecureRandom random = new SecureRandom();
        byte[] saltBytes = new byte[16];
        random.nextBytes(saltBytes);
        System.out.println(Base64.encodeBase64String(saltBytes));
    }

}
