package com.oracle.moneybagsauth;

import com.oracle.moneybagsauth.config.RsaKeyProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@EnableConfigurationProperties(RsaKeyProperties.class)
@SpringBootApplication
public class MoneybagsAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(MoneybagsAuthApplication.class, args);
    }

}
