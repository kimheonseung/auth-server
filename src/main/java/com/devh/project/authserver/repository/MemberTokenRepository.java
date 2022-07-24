package com.devh.project.authserver.repository;

import com.devh.project.authserver.domain.Member;
import com.devh.project.authserver.domain.MemberToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberTokenRepository extends JpaRepository<MemberToken, Long> {
    Optional<MemberToken> findByMember(Member member);
    boolean existsByMember(Member member);
    void deleteByMember(Member member);
}
