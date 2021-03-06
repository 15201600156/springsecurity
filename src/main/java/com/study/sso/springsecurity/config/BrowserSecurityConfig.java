package com.study.sso.springsecurity.config;

import com.study.sso.springsecurity.filter.SmsCodeFilter;
import com.study.sso.springsecurity.filter.ValidateCodeFilter;
import com.study.sso.springsecurity.handler.MyAuthenticationAccessDeniedHandler;
import com.study.sso.springsecurity.handler.MyAuthenticationFailureHandler;
import com.study.sso.springsecurity.handler.MyAuthenticationSucessHandler;
import com.study.sso.springsecurity.handler.MyLogOutSuccessHandler;
import com.study.sso.springsecurity.service.UserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;


@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class BrowserSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyAuthenticationSucessHandler authenticationSucessHandler;

    @Autowired
    private MyAuthenticationFailureHandler authenticationFailureHandler;

    @Autowired
    private ValidateCodeFilter validateCodeFilter;

    @Autowired
    private UserDetailService userDetailService;
    @Autowired
    private DataSource dataSource;


    //短信验证
    @Autowired
    private SmsCodeFilter smsCodeFilter;

    //expiredSessionStrategy配置了Session在并发下失效后的处理策略
    @Autowired
    private SmsAuthenticationConfig smsAuthenticationConfig;

    //退出成功后的逻辑
    @Autowired
    private MyLogOutSuccessHandler logOutSuccessHandler;

    @Autowired
    private MySessionExpiredStrategy sessionExpiredStrategy;

    //权限不足后的处理
    @Autowired
    private MyAuthenticationAccessDeniedHandler authenticationAccessDeniedHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.addFilterBefore(validateCodeFilter, UsernamePasswordAuthenticationFilter.class) // 添加验证码校验过滤器
                 .addFilterBefore(smsCodeFilter, UsernamePasswordAuthenticationFilter.class)// 添加短信验证码校验过滤器

                 .formLogin() // 表单登录
                // http.httpBasic() // HTTP Basic
                .loginPage("/login.html") // 登录跳转 URL
                .loginProcessingUrl("/login") //// 处理表单登录 URL
                .successHandler(authenticationSucessHandler) // 处理登录成功
                .failureHandler(authenticationFailureHandler) // 处理登录失败
         .and()
                .rememberMe() //记住我
                .tokenRepository(persistentTokenRepository()) // 配置 token 持久化仓库
                .tokenValiditySeconds(3600) // remember 过期时间，单为秒
                .userDetailsService(userDetailService) // 处理自动登录逻辑
         .and()
                .authorizeRequests() // 授权配置
                .antMatchers("/login.html").permitAll() //表示跳转到登录页面的请求不被拦截，否则会进入无限循环
                .antMatchers("/authentication/require").permitAll() // 登录跳转 URL 无需认证
                .antMatchers("/css/**","/code/image","/code/sms","/session/invalid","/signout/success").permitAll() //无需认证的请求
                .anyRequest()  // 所有请求
                .authenticated()// 都需要认证
         .and().csrf().disable() //CSRF攻击防御关了
                .apply(smsAuthenticationConfig) // 将短信验证码认证配置加到 Spring Security 中
         .and()
                .logout()
                .logoutUrl("/signout")
                .logoutSuccessHandler(logOutSuccessHandler)
               // .logoutSuccessUrl("/signout/success")
                .deleteCookies("JSESSIONID")
        .and()
                .sessionManagement() // 添加 Session管理器
                .invalidSessionUrl("/session/invalid") // Session失效后跳转到这个链接
                .maximumSessions(1)   //配置了最大Session并发数量为1个
                .maxSessionsPreventsLogin(true)
                .expiredSessionStrategy(sessionExpiredStrategy); //Session在并发下失效后的处理策略

         http.exceptionHandling()
                .accessDeniedHandler(authenticationAccessDeniedHandler);

    }

    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(dataSource);
        jdbcTokenRepository.setCreateTableOnStartup(false);
        return jdbcTokenRepository;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }



}