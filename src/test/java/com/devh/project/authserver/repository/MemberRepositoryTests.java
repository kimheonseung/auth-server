package com.devh.project.authserver.repository;

import com.devh.project.authserver.domain.Member;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.TestPropertySource;

import java.util.NoSuchElementException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@TestPropertySource(properties = {"spring.config.location=classpath:application-test.yml"})
public class MemberRepositoryTests {
    @Autowired
    private MemberRepository memberRepository;

    @BeforeEach
    public void beforeEach() {
        memberRepository.save(Member.builder()
                .id(1L)
                .email("devh@devh.com")
                .password("password")
            .build()
        );
    }

    @Nested
    @DisplayName("성공")
    class Success {
        @Test
        public void findByEmail() {
            // given
            final String givenEmail = "devh@devh.com";
            // when
            Member member = memberRepository.findByEmail(givenEmail).orElseThrow();
            // then
            assertEquals(member.getEmail(), givenEmail);
        }
        @Test
        public void existsByEmail() {
            // given
            final String givenEmail = "devh@devh.com";
            // when
            boolean exists = memberRepository.existsByEmail(givenEmail);
            // then
            assertTrue(exists);
        }
    }

    @Nested
    @DisplayName("실패")
    class Fail {
        @Test
        public void findByEmail() {
            // given
            final String givenEmail = "error@devh.com";
            // then
            assertThrows(NoSuchElementException.class, () -> memberRepository.findByEmail(givenEmail).orElseThrow());
        }
        @Test
        public void existsByEmail() {
            // given
            final String givenEmail = "error@devh.com";
            // when
            boolean exists = memberRepository.existsByEmail(givenEmail);
            // then
            assertFalse(exists);
        }
    }

}
