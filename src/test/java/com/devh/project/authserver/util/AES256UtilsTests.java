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
        final String givenString = "tMUSeRyXcMH9gaZ7wFGs1aFVVj22NFPbwTZhhFvDXbuLdU+Ym2QoyydNF5M1T7gg";
        // when
        String decryptedString = aes256Utils.decrypt(givenString);
        // then
        assertEquals(decryptedString, "test");
    }

    @Test
    public void decryptByCryptoJS() throws Exception {
        // given
        final String givenString = "21ac82b912eaa161f7a38331409f2760cb82b51f9d3285151fe158ef0dace117LuvDo/pdkFLGF3LvnmCyjg==";
        // when
        String decryptedString = aes256Utils.decryptByCryptoJS(givenString);
        // then
        assertEquals(decryptedString, "test");
    }

}
