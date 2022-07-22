package com.devh.project.authserver.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

import java.security.InvalidKeyException;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
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

@ExtendWith(MockitoExtension.class)
@Transactional
public class MemberServiceTests {
    @Mock
    private MemberRepository memberRepository;
    @Mock
    private RedisMemberRepository redisMemberRepository;
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
            final String givenPassword = "+DaT3ChVfxFiO3i7g6FPHFxlenMROTVUb+fJSh9/XGcFVaivRC+v5lJcq2ps2nK0V1lpEg=="; // test
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
    }

    @Nested
    @DisplayName("실패")
    class Fail {
        @Test
        public void signUpByMemberSignUpRequestVO_duplicate_email() {
            // given
            final String givenEmail = "devh@devh.com";
            final String givenPassword = "+DaT3ChVfxFiO3i7g6FPHFxlenMROTVUb+fJSh9/XGcFVaivRC+v5lJcq2ps2nK0V1lpEg=="; // test
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
            final String givenPassword = "+DaT3ChVfxFiO3i7g6FPHFxlenMROTVUb+fJSh9/XGcFVaivRC+v5lJcq2ps2nK0V1lpEg=="; // test
            final String givenName = "devh";
            final MemberSignUpRequestVO memberSignUpRequestVO = new MemberSignUpRequestVO(givenEmail, givenName, givenPassword);
            given(memberRepository.existsByEmail(givenEmail)).willReturn(false);
            given(aes256Utils.decrypt(givenPassword)).willThrow(new InvalidKeyException("password error test !"));
            // then
            assertThrows(PasswordException.class, () -> memberService.signUpByMemberSignUpRequestVO(memberSignUpRequestVO));
        }
    }
}
