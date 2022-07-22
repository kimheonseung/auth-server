package com.devh.project.authserver.repository;

import org.springframework.data.repository.CrudRepository;

import com.devh.project.authserver.domain.RedisMember;

public interface RedisMemberRepository extends CrudRepository<RedisMember, String> {
}
