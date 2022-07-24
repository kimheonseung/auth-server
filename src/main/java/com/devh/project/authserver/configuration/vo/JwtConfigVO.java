package com.devh.project.authserver.configuration.vo;

import lombok.Data;

@Data
public class JwtConfigVO {
    private String issuer = "devh";
    private String secretKey;
    private String header;
    private Expire expire;
    @Data
    public static class Expire {
        private int access = 10;
        private int refresh = 60;
    }
}
