package com.devh.project.authserver.configuration.vo;

import lombok.Data;

@Data
public class MailConfigVO {
    private String host = "smtp.gmail.com";
    private int port = 587;
    private String username;
    private String password;
    private Smtp smtp = new Smtp();

    @Data
    public static class Smtp {
        private Starttls starttls = new Starttls();
        private boolean auth = true;
        private int connectiontimeout = 5000;
        private int timeout = 5000;
        private int writetimeout = 5000;
        @Data
        public static class Starttls {
            private boolean enable = true;
            private boolean required = true;
        }
    }
}
