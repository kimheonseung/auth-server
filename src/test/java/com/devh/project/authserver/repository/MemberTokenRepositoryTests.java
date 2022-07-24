package com.devh.project.authserver.repository;

import com.devh.project.authserver.domain.Member;
import com.devh.project.authserver.domain.MemberToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.TestPropertySource;

import java.util.NoSuchElementException;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@TestPropertySource(properties = {"spring.config.location=classpath:application-test.yml"})
public class MemberTokenRepositoryTests {
    @Autowired
    private MemberRepository memberRepository;
    @Autowired
    private MemberTokenRepository memberTokenRepository;

    @BeforeEach
    public void beforeEach() {
        Member member = Member.builder()
                .email("test@test.com")
                .name("test")
                .password(new BCryptPasswordEncoder().encode("test"))
                .build();
        Member savedMember = memberRepository.save(member);
        memberTokenRepository.save(MemberToken.builder()
                .member(savedMember)
                .refreshToken("refreshToken")
            .build());
    }

    @Test
    public void findByMember() {
        Member member = memberRepository.findByEmail("test@test.com").orElseThrow();
        MemberToken memberToken = memberTokenRepository.findByMember(member).orElseThrow();
        System.out.println(memberToken);
    }

    @Test
    public void deleteByMember() {
        Member member = memberRepository.findByEmail("test@test.com").orElseThrow();
        System.out.println(memberTokenRepository.findByMember(member).orElseThrow());
        memberTokenRepository.deleteByMember(member);
        assertThrows(NoSuchElementException.class, () -> memberTokenRepository.findByMember(member).orElseThrow(NoSuchElementException::new));
    }
}
