package oit.is.team6.lec03.security.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class Sample3AuthConfiguration {

  /**
   * 認証処理に関する設定（誰がどのようなロールでログインできるか）
   * @param http
   * @return
   * @throws Exception
   */
  
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
    http.formLogin( login -> login
        .permitAll())
        .logout(logout -> logout
            .logoutUrl("/logout")
            .logoutSuccessUrl("/"))
        .authorizeHttpRequests(authz -> authz 
            .requestMatchers(AntPathRequestMatcher.antMatcher("/sample3/**")).authenticated()
            .requestMatchers(AntPathRequestMatcher.antMatcher("/**")).permitAll());
    return http.build();
  }
  public InMemoryUserDetailsManager userDetailsService() {

    // ユーザ名，パスワード，ロールを指定してbuildする
    // このときパスワードはBCryptでハッシュ化されているため，{bcrypt}とつける
    // ハッシュ化せずに平文でパスワードを指定する場合は{noop}をつける
    // ハッシュ化されたパスワードを得るには，この授業のbashターミナルで下記のように末尾にユーザ名とパスワードを指定すると良い(要VPN)
    // $ sshrun htpasswd -nbBC 10 user1 p@ss

    UserDetails user = User.withUsername("ogawa")
        .password("{bcrypt}$2y$10$1ugrOrcqaiqN3a2Flpl8N.56KuAKhrImvQqfA4uOTO3NmFHpvzTw2").roles("USER").build();

    UserDetails admin = User.withUsername("shinsaku")
        .password("{bcrypt}$2y$10$EyAslQ.sI62.pRvtnAwgQ.mpyzNa3VsZvWkFWQgDC0upTtAq5RCqG").roles("ADMIN").build();

    // 生成したユーザをImMemoryUserDetailsManagerに渡す（いくつでも良い）
    return new InMemoryUserDetailsManager(user, admin);
  }

}
