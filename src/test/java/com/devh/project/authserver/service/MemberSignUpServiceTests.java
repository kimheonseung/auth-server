package com.devh.project.authserver.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doNothing;

import java.security.InvalidKeyException;
import java.util.Optional;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.annotation.Transactional;

import com.devh.project.authserver.constant.SignUpStatus;
import com.devh.project.authserver.domain.Member;
import com.devh.project.authserver.domain.RedisMember;
import com.devh.project.authserver.dto.member.SignUpRequestDTO;
import com.devh.project.authserver.dto.member.SignUpResponseDTO;
import com.devh.project.authserver.exception.DuplicateEmailException;
import com.devh.project.authserver.exception.PasswordException;
import com.devh.project.authserver.exception.SignUpException;
import com.devh.project.authserver.helper.AES256Helper;
import com.devh.project.authserver.helper.AuthKeyHelper;
import com.devh.project.authserver.helper.BCryptHelper;
import com.devh.project.authserver.helper.JwtHelper;
import com.devh.project.authserver.repository.MemberRepository;
import com.devh.project.authserver.repository.MemberTokenRepository;
import com.devh.project.authserver.repository.RedisMemberRepository;

@ExtendWith(MockitoExtension.class)
@Transactional
public class MemberSignUpServiceTests {
    @Mock
    private MemberRepository memberRepository;
    @Mock
    private MemberTokenRepository memberTokenRepository;
    @Mock
    private RedisMemberRepository redisMemberRepository;
    @Mock
    private JwtHelper jwtHelper;
    @Mock
    private BCryptHelper bcryptHelper;
    @Mock
    private AuthKeyHelper authKeyHelper;
    @Mock
    private AES256Helper aes256Helper;
    @Mock
    private MailService mailService;
    @InjectMocks
    private MemberSignUpService memberSignUpService;

    @Nested
    @DisplayName("성공")
    class Success {
    	@Test
        @DisplayName("가입 요청 - 인증메일 전송 로직")
        public void signUpByMemberSignUpRequestVO() throws Exception {
            // given
            final String givenEmail = "devh@devh.com";
            final String givenPassword = "tMUSeRyXcMH9gaZ7wFGs1aFVVj22NFPbwTZhhFvDXbuLdU+Ym2QoyydNF5M1T7gg"; // test
            final String givenName = "devh";
            final SignUpRequestDTO signUpRequestDTO = SignUpRequestDTO.builder()
                    .email(givenEmail)
                    .name(givenName)
                    .password(givenPassword)
                    .build();
            given(memberRepository.existsByEmail(givenEmail)).willReturn(false);
            given(redisMemberRepository.save(any(RedisMember.class))).willReturn(RedisMember.builder()
                    .email(givenEmail)
                    .name(givenName)
                    .password(givenPassword)
                    .authKey("authKey")
                    .build());
            doNothing().when(mailService).sendSignupValidationMail(any(String.class), any(String.class));
            given(aes256Helper.decrypt(givenPassword)).willReturn("test");
            // when
            SignUpResponseDTO signUpResponseDTO = memberSignUpService.signUpByMemberSignUpRequestVO(signUpRequestDTO);
            // then
            assertEquals(signUpResponseDTO.getSignUpStatus(), SignUpStatus.REQUESTED);
            assertEquals(signUpResponseDTO.getEmail(), givenEmail);
        }

        @Test
        @DisplayName("인증메일을 통해 임시 회원 정보 DB 저장 로직")
        public void commitSignUpByEmailAndAuthKey() {
            // given
            final String givenEmail = "test@test.com";
            final String givenAuthKey = "authKey";
            given(redisMemberRepository.findById(givenEmail)).willReturn(Optional.of(RedisMember.builder()
                    .email(givenEmail)
                    .name("test")
                    .authKey(givenAuthKey)
                    .build()));
            given(memberRepository.existsByEmail(givenEmail)).willReturn(false);
            given(memberRepository.save(any(Member.class))).willAnswer(i -> i.getArguments()[0]);
            // when
            SignUpResponseDTO signUpResponseDTO = memberSignUpService.commitSignUpByEmailAndAuthKey(givenEmail, givenAuthKey);
            // then
            assertEquals(signUpResponseDTO.getSignUpStatus(), SignUpStatus.COMPLETED);
            assertEquals(signUpResponseDTO.getEmail(), givenEmail);
        }
    }

    @Nested
    @DisplayName("실패")
    class Fail {
    	@Test
        @DisplayName("가입 요청 - 중복 email")
        public void signUpByMemberSignUpRequestVO_duplicate_email() {
            // given
            final String givenEmail = "devh@devh.com";
            final String givenPassword = "tMUSeRyXcMH9gaZ7wFGs1aFVVj22NFPbwTZhhFvDXbuLdU+Ym2QoyydNF5M1T7gg"; // test
            final String givenName = "devh";
            final SignUpRequestDTO signUpRequestDTO = SignUpRequestDTO.builder()
                    .email(givenEmail)
                    .name(givenName)
                    .password(givenPassword)
                    .build();
            given(memberRepository.existsByEmail(givenEmail)).willReturn(true);
            // then
            assertThrows(DuplicateEmailException.class, () -> memberSignUpService.signUpByMemberSignUpRequestVO(signUpRequestDTO));
        }

        @Test
        @DisplayName("가입 요청 - 비밀번호 예외")
        public void signUpByMemberSignUpRequestVO_password() throws Exception {
            // given
            final String givenEmail = "devh@devh.com";
            final String givenPassword = "tMUSeRyXcMH9gaZ7wFGs1aFVVj22NFPbwTZhhFvDXbuLdU+Ym2QoyydNF5M1T7gg"; // test
            final String givenName = "devh";
            final SignUpRequestDTO signUpRequestDTO = SignUpRequestDTO.builder()
                    .email(givenEmail)
                    .name(givenName)
                    .password(givenPassword)
                    .build();
            given(memberRepository.existsByEmail(givenEmail)).willReturn(false);
            given(aes256Helper.decrypt(givenPassword)).willThrow(new InvalidKeyException("password error test !"));
            // then
            assertThrows(PasswordException.class, () -> memberSignUpService.signUpByMemberSignUpRequestVO(signUpRequestDTO));
        }

        @Test
        @DisplayName("인증메일 검증 - 레디스에 해당 정보가 존재하지 않음")
        public void commitSignUpByEmailAndAuthKey_redis_error() {
            // given
            final String givenEmail = "test@test.com";
            final String givenAuthKey = "authKey";
            given(redisMemberRepository.findById(givenEmail)).willReturn(Optional.empty());
            // then
            assertThrows(SignUpException.class, () -> memberSignUpService.commitSignUpByEmailAndAuthKey(givenEmail, givenAuthKey));
        }

        @Test
        @DisplayName("인증메일 검증 - 발급한 authKey와 다른 authKey 수신")
        public void commitSignUpByEmailAndAuthKey_authKey_error() {
            // given
            final String givenEmail = "test@test.com";
            final String givenAuthKey = "authKey";
            given(redisMemberRepository.findById(givenEmail)).willReturn(Optional.of(RedisMember.builder()
                    .email(givenEmail)
                    .name("test")
                    .password("$2a$10$XOzzm0y.T5QU6Reb6TUyUusBodpFNzcHJEYUZ0YikF3bF9h7ZMsdO")
                    .authKey("different" + givenAuthKey)
                    .build()));
            // then
            assertThrows(SignUpException.class, () -> memberSignUpService.commitSignUpByEmailAndAuthKey(givenEmail, givenAuthKey));
        }

        @Test
        @DisplayName("인증메일 검증 - 이미 회원이 존재함")
        public void commitSignUpByEmailAndAuthKey_alreadyExists_error() {
            // given
            final String givenEmail = "test@test.com";
            final String givenAuthKey = "authKey";
            given(redisMemberRepository.findById(givenEmail)).willReturn(Optional.of(RedisMember.builder()
                    .email(givenEmail)
                    .name("test")
                    .password("$2a$10$XOzzm0y.T5QU6Reb6TUyUusBodpFNzcHJEYUZ0YikF3bF9h7ZMsdO")
                    .authKey(givenAuthKey)
                    .build()));
            given(memberRepository.existsByEmail(givenEmail)).willReturn(true);
            // then
            assertThrows(SignUpException.class, () -> memberSignUpService.commitSignUpByEmailAndAuthKey(givenEmail, givenAuthKey));
        }
    }
}
