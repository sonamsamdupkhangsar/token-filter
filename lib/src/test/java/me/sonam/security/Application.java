package me.sonam.security;

import io.r2dbc.spi.ConnectionFactory;
import me.sonam.security.headerfilter.ReactiveRequestContextHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.r2dbc.connection.init.ConnectionFactoryInitializer;
import org.springframework.r2dbc.connection.init.ResourceDatabasePopulator;
import org.springframework.web.reactive.function.client.WebClient;

@SpringBootApplication
public class Application implements CommandLineRunner {
    private static final Logger LOG = LoggerFactory.getLogger(Application.class);

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
    @Value("${tokenExpireSeconds:1}")
    private int tokenExpireSeconds;

    @Override
    public void run(String... args) {

    }

    @Bean()
    ConnectionFactoryInitializer initializer(ConnectionFactory connectionFactory) {
        ConnectionFactoryInitializer initializer = new ConnectionFactoryInitializer();
        initializer.setConnectionFactory(connectionFactory);
        // This will create our database table and schema
        initializer.setDatabasePopulator(new ResourceDatabasePopulator(new ClassPathResource("schema.sql")));

        // This will drop our table after we are done so we can have a fresh start next run
        //initializer.setDatabaseCleaner(new ResourceDatabasePopulator(new ClassPathResource("cleanup.sql")));
        return initializer;
    }

    @Bean
    public WebClient.Builder testWebClient() {
        return WebClient.builder();
    }

    @Bean
    public ReactiveRequestContextHolder reactiveRequestContextHolder() {
        return new ReactiveRequestContextHolder(testWebClient(), tokenExpireSeconds);
    }

}
