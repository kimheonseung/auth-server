package com.devh.project.authserver.configuration;

import com.devh.project.authserver.configuration.vo.MailConfigVO;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.PropertiesPropertySource;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import java.io.FileReader;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.util.Properties;

public class EnvironmentPostProcessorImpl implements EnvironmentPostProcessor {

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        try {
            MailConfigVO mailConfigVO = new Yaml(new Constructor(MailConfigVO.class)).load(new FileReader("config/mail-config.yml"));
            Properties mailProperties = new Properties();
            mailProperties.put("mail.host", mailConfigVO.getHost());
            mailProperties.put("mail.port", mailConfigVO.getPort());
            mailProperties.put("mail.username", mailConfigVO.getUsername());
            mailProperties.put("mail.password", mailConfigVO.getPassword());
            mailProperties.put("mail.smtp.starttls.enable", mailConfigVO.getSmtp().getStarttls().isEnable());
            mailProperties.put("mail.smtp.starttls.required", mailConfigVO.getSmtp().getStarttls().isRequired());
            mailProperties.put("mail.smtp.auth", mailConfigVO.getSmtp().isAuth());
            mailProperties.put("mail.smtp.connectiontimeout", mailConfigVO.getSmtp().getConnectiontimeout());
            mailProperties.put("mail.smtp.timeout", mailConfigVO.getSmtp().getTimeout());
            mailProperties.put("mail.smtp.writetimeout", mailConfigVO.getSmtp().getWritetimeout());
            environment.getPropertySources().addFirst(new PropertiesPropertySource("mail", mailProperties));
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Failed to start post process ... - " + e.getMessage());
            System.exit(0);
        }

    }

    private void databaseConnectionTest(String url, String username, String password) {
        boolean isConnected = false;
        while(!isConnected) {
            try (
                    Connection conn = DriverManager.getConnection(url, username, password)
            ) {
                DatabaseMetaData metadata = conn.getMetaData();
                System.out.printf("%s - %d.%d [%s - %s]%n",
                        metadata.getDatabaseProductName(),
                        metadata.getDatabaseMajorVersion(),
                        metadata.getDatabaseMinorVersion(),
                        metadata.getDriverName(),
                        metadata.getDriverVersion()
                );
                isConnected = true;
                System.out.println("Success to test database connection !");
            } catch (Exception e) {
                System.out.println("Failed to test database connection ... - " + e.getMessage());
                try { Thread.sleep(3000L); } catch (InterruptedException ignored) {}
            }
        }
    }
}