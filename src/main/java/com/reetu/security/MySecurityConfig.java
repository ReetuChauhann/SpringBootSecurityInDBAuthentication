package com.reetu.security;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;

@Configuration
@EnableWebSecurity
public class MySecurityConfig extends WebSecurityConfigurerAdapter {
                    @Autowired
                    DataSource datasource;
                   
                    @Override
                    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
                    	auth.jdbcAuthentication().dataSource(datasource)
                    	.passwordEncoder(NoOpPasswordEncoder.getInstance())
                    	.usersByUsernameQuery("select username,password,enabled from users where username=?")
                    	.authoritiesByUsernameQuery("select username,role from users where username=?");
                    }
                    
                    @Override 
                    protected void configure(HttpSecurity http) throws Exception{
                    	http.authorizeRequests()
                    	.antMatchers("/").permitAll()
                    	.antMatchers("/demo1").hasAnyRole("USER")
                    	.antMatchers("/demo2").hasAnyRole("USER","ADMIN") //keep role in capital and role_user in DB (not only user and small/capital does not matter)
                    	.and().formLogin().permitAll()
                    	.and().logout().logoutSuccessUrl("/").permitAll() //optional
                    	.and().exceptionHandling().accessDeniedPage("/accessDenied");
                    }
                    
}
