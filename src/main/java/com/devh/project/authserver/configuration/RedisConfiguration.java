package com.devh.project.authserver.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;

@Configuration
@EnableRedisHttpSession(maxInactiveIntervalInSeconds = 10)
public class RedisConfiguration {
	
	@Value("${spring.redis.host}")
	private String host;
	@Value("${spring.redis.port}")
    private int port;
	// insert into member (3, 'test@test.com', 'test', '$2a$10$z4rMdczsrb68yyim0bPPy.MNN50CFaxH9poivMoWQXtdx9utMTPxG');
	@Bean
    public RedisConnectionFactory redisConnectionFactory() {
        return new LettuceConnectionFactory(host, port);
    }
}
