package com.devh.project.authserver.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Optional;

import com.devh.project.authserver.constant.TokenStatus;
import com.devh.project.authserver.domain.Member;
import com.devh.project.authserver.util.JwtUtils;
import com.devh.project.authserver.vo.MemberLoginRequestVO;
import com.devh.project.authserver.vo.MemberLoginResponseVO;
import com.devh.project.authserver.vo.TokenVO;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import com.devh.project.authserver.constant.SignUpStatus;
import com.devh.project.authserver.domain.RedisMember;
import com.devh.project.authserver.exception.DuplicateEmailException;
import com.devh.project.authserver.exception.PasswordException;
import com.devh.project.authserver.repository.MemberRepository;
import com.devh.project.authserver.repository.RedisMemberRepository;
import com.devh.project.authserver.util.AES256Utils;
import com.devh.project.authserver.vo.MemberSignUpRequestVO;
import com.devh.project.authserver.vo.MemberSignUpResponseVO;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

@ExtendWith(MockitoExtension.class)
@Transactional
public class MemberServiceTests {
    @Mock
    private MemberRepository memberRepository;
    @Mock
    private RedisMemberRepository redisMemberRepository;
    @Mock
    private JwtUtils jwtUtils;
    @Mock
    private AES256Utils aes256Utils;
    @InjectMocks
    private MemberService memberService;

    @Nested
    @DisplayName("성공")
    class Success {
        @Test
        public void signUpByMemberSignUpRequestVO() throws Exception {
            // given
            final String givenEmail = "devh@devh.com";
            final String givenPassword = "tMUSeRyXcMH9gaZ7wFGs1aFVVj22NFPbwTZhhFvDXbuLdU+Ym2QoyydNF5M1T7gg"; // test
            final String givenName = "devh";
            final MemberSignUpRequestVO memberSignUpRequestVO = new MemberSignUpRequestVO(givenEmail, givenName, givenPassword);
            given(memberRepository.existsByEmail(givenEmail)).willReturn(false);
            given(redisMemberRepository.save(any(RedisMember.class))).willReturn(RedisMember.builder()
            		.email(givenEmail)
            		.name(givenName)
            		.password(givenPassword)
            		.authKey("authKey")
            		.build());
            given(aes256Utils.decrypt(givenPassword)).willReturn("password");
            // when
            MemberSignUpResponseVO memberSignUpResponseVO = memberService.signUpByMemberSignUpRequestVO(memberSignUpRequestVO);
            // then
            assertEquals(memberSignUpResponseVO.getSignUpStatus(), SignUpStatus.REQUESTED);
            assertEquals(memberSignUpResponseVO.getEmail(), givenEmail);
        }

        @Test
        public void login() throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException {
            // given
            final String givenMemberEmail = "test@test.com";
            final String givenPassword = "tMUSeRyXcMH9gaZ7wFGs1aFVVj22NFPbwTZhhFvDXbuLdU+Ym2QoyydNF5M1T7gg";
            final String givenAccessToken = "accessToken";
            final String givenRefreshToken = "refreshToken";
            given(aes256Utils.decrypt(givenPassword)).willReturn("test");
            given(memberRepository.findByEmail(givenMemberEmail)).willReturn(Optional.of(Member.builder()
                .email(givenMemberEmail)
                .name("name")
                .password(new BCryptPasswordEncoder().encode("test"))
            .build()));
            given(jwtUtils.generateTokenByEmail(givenMemberEmail)).willReturn(TokenVO.builder()
                .tokenStatus(TokenStatus.LOGIN_SUCCESS)
                .accessToken(givenAccessToken)
                .refreshToken(givenRefreshToken)
            .build());
            // when
            MemberLoginResponseVO memberLoginResponseVO = memberService.login(new MemberLoginRequestVO(givenMemberEmail, givenPassword));
            // then
            assertEquals(memberLoginResponseVO.getToken().getTokenStatus(), TokenStatus.LOGIN_SUCCESS);
            assertEquals(memberLoginResponseVO.getToken().getAccessToken(), givenAccessToken);
            assertEquals(memberLoginResponseVO.getToken().getRefreshToken(), givenRefreshToken);
        }

        @Test
        public void logout() {

        }
    }

    @Nested
    @DisplayName("실패")
    class Fail {
        @Test
        public void signUpByMemberSignUpRequestVO_duplicate_email() {
            // given
            final String givenEmail = "devh@devh.com";
            final String givenPassword = "tMUSeRyXcMH9gaZ7wFGs1aFVVj22NFPbwTZhhFvDXbuLdU+Ym2QoyydNF5M1T7gg"; // test
            final String givenName = "devh";
            final MemberSignUpRequestVO memberSignUpRequestVO = new MemberSignUpRequestVO(givenEmail, givenName, givenPassword);
            given(memberRepository.existsByEmail(givenEmail)).willReturn(true);
            // then
            assertThrows(DuplicateEmailException.class, () -> memberService.signUpByMemberSignUpRequestVO(memberSignUpRequestVO));
        }
        @Test
        public void signUpByMemberSignUpRequestVO_password() throws Exception {
            // given
            final String givenEmail = "devh@devh.com";
            final String givenPassword = "tMUSeRyXcMH9gaZ7wFGs1aFVVj22NFPbwTZhhFvDXbuLdU+Ym2QoyydNF5M1T7gg"; // test
            final String givenName = "devh";
            final MemberSignUpRequestVO memberSignUpRequestVO = new MemberSignUpRequestVO(givenEmail, givenName, givenPassword);
            given(memberRepository.existsByEmail(givenEmail)).willReturn(false);
            given(aes256Utils.decrypt(givenPassword)).willThrow(new InvalidKeyException("password error test !"));
            // then
            assertThrows(PasswordException.class, () -> memberService.signUpByMemberSignUpRequestVO(memberSignUpRequestVO));
        }
    }
}
