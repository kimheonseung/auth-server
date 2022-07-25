package com.devh.project.authserver.service;

import com.devh.project.authserver.constant.SignUpStatus;
import com.devh.project.authserver.constant.TokenStatus;
import com.devh.project.authserver.domain.Member;
import com.devh.project.authserver.domain.MemberToken;
import com.devh.project.authserver.domain.RedisMember;
import com.devh.project.authserver.dto.TokenDTO;
import com.devh.project.authserver.dto.member.LoginRequestDTO;
import com.devh.project.authserver.dto.member.LoginResponseDTO;
import com.devh.project.authserver.dto.member.LogoutRequestDTO;
import com.devh.project.authserver.dto.member.LogoutResponseDTO;
import com.devh.project.authserver.dto.member.RefreshRequestDTO;
import com.devh.project.authserver.dto.member.RefreshResponseDTO;
import com.devh.project.authserver.dto.member.SignUpRequestDTO;
import com.devh.project.authserver.dto.member.SignUpResponseDTO;
import com.devh.project.authserver.exception.DuplicateEmailException;
import com.devh.project.authserver.exception.LoginException;
import com.devh.project.authserver.exception.PasswordException;
import com.devh.project.authserver.exception.SignUpException;
import com.devh.project.authserver.repository.MemberRepository;
import com.devh.project.authserver.repository.MemberTokenRepository;
import com.devh.project.authserver.repository.RedisMemberRepository;
import com.devh.project.authserver.util.AES256Utils;
import com.devh.project.authserver.util.AuthKeyUtils;
import com.devh.project.authserver.util.BCryptUtils;
import com.devh.project.authserver.util.JwtUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.servlet.http.HttpServletRequest;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doNothing;

@ExtendWith(MockitoExtension.class)
@Transactional
public class MemberServiceTests {
    @Mock
    private MemberRepository memberRepository;
    @Mock
    private MemberTokenRepository memberTokenRepository;
    @Mock
    private RedisMemberRepository redisMemberRepository;
    @Mock
    private JwtUtils jwtUtils;
    @Mock
    private BCryptUtils bcryptUtils;
    @Mock
    private AuthKeyUtils authKeyUtils;
    @Mock
    private AES256Utils aes256Utils;
    @Mock
    private MailService mailService;
    @InjectMocks
    private MemberService memberService;

    @Nested
    @DisplayName("성공")
    class Success {
        @Nested
        @DisplayName("회원 가입")
        class SignUp {
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
                given(aes256Utils.decrypt(givenPassword)).willReturn("test");
                // when
                SignUpResponseDTO signUpResponseDTO = memberService.signUpByMemberSignUpRequestVO(signUpRequestDTO);
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
                SignUpResponseDTO signUpResponseDTO = memberService.commitSignUpByEmailAndAuthKey(givenEmail, givenAuthKey);
                // then
                assertEquals(signUpResponseDTO.getSignUpStatus(), SignUpStatus.COMPLETED);
                assertEquals(signUpResponseDTO.getEmail(), givenEmail);
            }
        }

        @Test
        @DisplayName("로그인 - 토큰 발급 로직")
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
            given(bcryptUtils.matches(any(String.class), any(String.class))).willReturn(true);
            given(jwtUtils.generateTokenByEmail(givenMemberEmail)).willReturn(TokenDTO.builder()
                    .tokenStatus(TokenStatus.LOGIN_SUCCESS)
                    .accessToken(givenAccessToken)
                    .refreshToken(givenRefreshToken)
                    .build());
            // when
            LoginResponseDTO loginResponseDTO = memberService.login(LoginRequestDTO.builder().email(givenMemberEmail).password(givenPassword).build());
            // then
            assertEquals(loginResponseDTO.getToken().getTokenStatus(), TokenStatus.LOGIN_SUCCESS);
            assertEquals(loginResponseDTO.getToken().getAccessToken(), givenAccessToken);
            assertEquals(loginResponseDTO.getToken().getRefreshToken(), givenRefreshToken);
        }

        @Test
        @DisplayName("로그아웃 - 토큰 제거")
        public void logout() throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
            // given
            final String givenEmail = "test@test.com";
            given(jwtUtils.getEmailFromRequest(any(HttpServletRequest.class))).willReturn(givenEmail);
            given(memberRepository.findByEmail(givenEmail)).willReturn(Optional.of(Member.builder()
                    .id(1L)
                    .email(givenEmail)
                    .password("$2a$10$XOzzm0y.T5QU6Reb6TUyUusBodpFNzcHJEYUZ0YikF3bF9h7ZMsdO")
                    .build()));
            // when
            LogoutResponseDTO response = memberService.logout(LogoutRequestDTO.builder().email(givenEmail).build(), new MockHttpServletRequest());
            System.out.println(response);
        }

        @Test
        @DisplayName("기존 토큰 만료 - 재발급 로직")
        public void refresh() {
            // given
            final String givenEmail = "test@test.com";
            final String givenAccessToken = "access";
            final String givenRefreshToken = "refresh";
            final Member givenMember = Member.builder()
                    .id(1L)
                    .email(givenEmail)
                    .name("test")
                    .password("$2a$10$XOzzm0y.T5QU6Reb6TUyUusBodpFNzcHJEYUZ0YikF3bF9h7ZMsdO")
                    .build();
            final TokenDTO tokenDTO = TokenDTO.builder().accessToken(givenAccessToken).refreshToken(givenRefreshToken).build();
            given(jwtUtils.isTokenExpired(givenAccessToken)).willReturn(true);
            given(jwtUtils.isTokenExpired(givenRefreshToken)).willReturn(false);
            given(jwtUtils.getEmailFromToken(givenAccessToken)).willReturn(givenEmail);
            given(jwtUtils.generateTokenByEmail(givenEmail)).willReturn(TokenDTO.builder().accessToken("newAccess").refreshToken("newRefresh").build());
            given(memberRepository.findByEmail(givenEmail)).willReturn(Optional.of(givenMember));
            given(memberTokenRepository.findByMember(givenMember)).willReturn(Optional.of(MemberToken.builder()
                    .id(1L)
                    .member(givenMember)
                    .refreshToken(givenRefreshToken)
                    .build()));
            // when
            RefreshResponseDTO refreshResponseDTO = memberService.refresh(RefreshRequestDTO.builder().token(tokenDTO).build());
            // then
            assertEquals(refreshResponseDTO.getToken().getTokenStatus(), TokenStatus.REFRESH_SUCCESS);
            assertEquals(refreshResponseDTO.getToken().getAccessToken(), "newAccess");
            assertEquals(refreshResponseDTO.getToken().getRefreshToken(), "newRefresh");
        }
    }

    @Nested
    @DisplayName("실패")
    class Fail {
        @Nested
        @DisplayName("회원 가입")
        class SignUp {
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
                assertThrows(DuplicateEmailException.class, () -> memberService.signUpByMemberSignUpRequestVO(signUpRequestDTO));
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
                given(aes256Utils.decrypt(givenPassword)).willThrow(new InvalidKeyException("password error test !"));
                // then
                assertThrows(PasswordException.class, () -> memberService.signUpByMemberSignUpRequestVO(signUpRequestDTO));
            }

            @Test
            @DisplayName("인증메일 검증 - 레디스에 해당 정보가 존재하지 않음")
            public void commitSignUpByEmailAndAuthKey_redis_error() {
                // given
                final String givenEmail = "test@test.com";
                final String givenAuthKey = "authKey";
                given(redisMemberRepository.findById(givenEmail)).willReturn(Optional.empty());
                // then
                assertThrows(SignUpException.class, () -> memberService.commitSignUpByEmailAndAuthKey(givenEmail, givenAuthKey));
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
                assertThrows(SignUpException.class, () -> memberService.commitSignUpByEmailAndAuthKey(givenEmail, givenAuthKey));
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
                assertThrows(SignUpException.class, () -> memberService.commitSignUpByEmailAndAuthKey(givenEmail, givenAuthKey));
            }
        }

        @Nested
        @DisplayName("로그인")
        class Login {
            @Test
            @DisplayName("로그인 - 존재하지 않는 유저")
            public void login_notExists() throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
                // given
                final String givenEmail = "notExists@test.com";
                final String givenPassword = "tMUSeRyXcMH9gaZ7wFGs1aFVVj22NFPbwTZhhFvDXbuLdU+Ym2QoyydNF5M1T7gg";
                given(aes256Utils.decrypt(givenPassword)).willReturn("test");
                given(memberRepository.findByEmail(givenEmail)).willReturn(Optional.empty());
                // then
                assertThrows(LoginException.class, () -> memberService.login(LoginRequestDTO.builder().email(givenEmail).password(givenPassword).build()));
            }

            @Test
            @DisplayName("로그인 - 비밀번호 예외")
            public void login_password() throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
                // given
                final String givenEmail = "test@test.com";
                final String givenPassword = "tMUSeRyXcMH9gaZ7wFGs1aFVVj22NFPbwTZhhFvDXbuLdU+Ym2QoyydNF5M1T7gg";
                given(aes256Utils.decrypt(givenPassword)).willReturn("test");
                given(memberRepository.findByEmail(givenEmail)).willReturn(Optional.of(Member.builder()
                        .id(1L)
                        .email(givenEmail)
                        .password("$2a$10$XOzzm0y.T5QU6Reb6TUyUusBodpFNzcHJEYUZ0YikF3bF9h7ZMsdO")
                        .name("test")
                        .build()));
                given(bcryptUtils.matches("test", "$2a$10$XOzzm0y.T5QU6Reb6TUyUusBodpFNzcHJEYUZ0YikF3bF9h7ZMsdO")).willReturn(false);
                // then
                assertThrows(LoginException.class, () -> memberService.login(LoginRequestDTO.builder().email(givenEmail).password(givenPassword).build()));
            }
        }

        @Nested
        @DisplayName("토큰 갱신")
        class Refresh {
            @Test
            @DisplayName("Access Token이 아직 유효함")
            public void refresh_access_notExpire() {
                // given
                final String givenAccessToken = "access";
                final String givenRefreshToken = "refresh";
                given(jwtUtils.isTokenExpired(givenAccessToken)).willReturn(false);
                // when
                RefreshResponseDTO refreshResponseDTO = memberService.refresh(RefreshRequestDTO.builder()
                        .token(TokenDTO.builder().accessToken(givenAccessToken).refreshToken(givenRefreshToken).build())
                        .build());
                // then
                assertEquals(refreshResponseDTO.getToken().getTokenStatus(), TokenStatus.ACCESS_TOKEN_NOT_EXPIRED);
            }

            @Test
            @DisplayName("Refresh Token이 만료됨")
            public void refresh_refreshExpire() {
                // given
                final String givenAccessToken = "access";
                final String givenRefreshToken = "refresh";
                given(jwtUtils.isTokenExpired(givenAccessToken)).willReturn(true);
                given(jwtUtils.isTokenExpired(givenRefreshToken)).willReturn(true);
                // when
                RefreshResponseDTO refreshResponseDTO = memberService.refresh(RefreshRequestDTO.builder()
                        .token(TokenDTO.builder().accessToken(givenAccessToken).refreshToken(givenRefreshToken).build())
                        .build());
                // then
                assertEquals(refreshResponseDTO.getToken().getTokenStatus(), TokenStatus.LOGIN_REQUIRED);
            }

            @Test
            @DisplayName("회원 정보가 정확하지 않음")
            public void refresh_invalid() {
                // given
                final String givenInvalidEmail = "invalidEmail@test.com";
                final String givenAccessToken = "access";
                final String givenRefreshToken = "refresh";
                given(jwtUtils.isTokenExpired(givenAccessToken)).willReturn(true);
                given(jwtUtils.getEmailFromToken(givenAccessToken)).willReturn(givenInvalidEmail);
                given(jwtUtils.isTokenExpired(givenRefreshToken)).willReturn(false);
                given(memberRepository.findByEmail(givenInvalidEmail)).willReturn(Optional.empty());
                // when
                RefreshResponseDTO refreshResponseDTO = memberService.refresh(RefreshRequestDTO.builder()
                        .token(TokenDTO.builder().accessToken(givenAccessToken).refreshToken(givenRefreshToken).build())
                        .build());
                // then
                assertEquals(refreshResponseDTO.getToken().getTokenStatus(), TokenStatus.INVALID);
            }

            @Test
            @DisplayName("기존 로그인 정보가 존재하지 않음 - 리프레시 토큰을 찾을 수 없음")
            public void refresh_refreshNotFound() {
                // given
                final String givenInvalidEmail = "invalidEmail@test.com";
                final String givenAccessToken = "access";
                final String givenRefreshToken = "refresh";
                final Member givenMember = Member.builder()
                        .id(1L)
                        .name("test")
                        .email(givenInvalidEmail)
                        .password("mockPassword")
                        .build();
                given(jwtUtils.isTokenExpired(givenAccessToken)).willReturn(true);
                given(jwtUtils.getEmailFromToken(givenAccessToken)).willReturn(givenInvalidEmail);
                given(jwtUtils.isTokenExpired(givenRefreshToken)).willReturn(false);
                given(memberRepository.findByEmail(givenInvalidEmail)).willReturn(Optional.of(givenMember));
                given(memberTokenRepository.findByMember(givenMember)).willReturn(Optional.empty());
                // when
                RefreshResponseDTO refreshResponseDTO = memberService.refresh(RefreshRequestDTO.builder()
                        .token(TokenDTO.builder().accessToken(givenAccessToken).refreshToken(givenRefreshToken).build())
                        .build());
                // then
                assertEquals(refreshResponseDTO.getToken().getTokenStatus(), TokenStatus.LOGIN_REQUIRED);
            }

            @Test
            @DisplayName("기존 로그인 정보가 존재하지 않음 - 리프레시 토큰이 같지 않음")
            public void refresh_refreshNotEquals() {
                // given
                final String givenInvalidEmail = "invalidEmail@test.com";
                final String givenAccessToken = "access";
                final String givenRefreshToken = "refresh";
                final Member givenMember = Member.builder()
                        .id(1L)
                        .name("test")
                        .email(givenInvalidEmail)
                        .password("mockPassword")
                        .build();
                given(jwtUtils.isTokenExpired(givenAccessToken)).willReturn(true);
                given(jwtUtils.getEmailFromToken(givenAccessToken)).willReturn(givenInvalidEmail);
                given(jwtUtils.isTokenExpired(givenRefreshToken)).willReturn(false);
                given(memberRepository.findByEmail(givenInvalidEmail)).willReturn(Optional.of(givenMember));
                given(memberTokenRepository.findByMember(givenMember)).willReturn(Optional.of(MemberToken.builder()
                        .id(1L)
                        .refreshToken("differentRefresh")
                        .member(givenMember)
                        .build()));
                // when
                RefreshResponseDTO refreshResponseDTO = memberService.refresh(RefreshRequestDTO.builder()
                        .token(TokenDTO.builder().accessToken(givenAccessToken).refreshToken(givenRefreshToken).build())
                        .build());
                // then
                assertEquals(refreshResponseDTO.getToken().getTokenStatus(), TokenStatus.REFRESH_FAIL);
            }
        }


    }
}
