package com.waf.processor.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;

import com.clickhouse.jdbc.ClickHouseDataSource;
import com.zaxxer.hikari.HikariConfig;
import java.sql.SQLException;
import com.zaxxer.hikari.HikariDataSource;

import javax.sql.DataSource;
import java.util.Properties;

@Configuration
public class ClickHouseConfig {

    @Value("${clickhouse.host:localhost}")
    private String host;

    @Value("${clickhouse.port:8123}")
    private int port;

    @Value("${clickhouse.database:security}")
    private String database;

    @Value("${clickhouse.username:default}")
    private String username;

    @Value("${clickhouse.password:}")
    private String password;

    @Bean
    public DataSource clickHouseDataSource() {
        String url = String.format("jdbc:clickhouse://%s:%d/%s", host, port, database);
        
        Properties props = new Properties();
        props.setProperty("user", username);
        if (password != null && !password.isEmpty()) {
            props.setProperty("password", password);
        }

        ClickHouseDataSource dataSource;
        try {
            dataSource = new ClickHouseDataSource(url, props);
        } catch (SQLException e) {
            throw new RuntimeException("Failed to create ClickHouse DataSource", e);
        }

        HikariConfig config = new HikariConfig();
        config.setDataSource(dataSource);
        config.setMaximumPoolSize(10);
        config.setMinimumIdle(2);
        config.setConnectionTimeout(5000);

        return new HikariDataSource(config);
    }

    @Bean
    public JdbcTemplate clickHouseJdbcTemplate(DataSource dataSource) {
        return new JdbcTemplate(dataSource);
    }
}