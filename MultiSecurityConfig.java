
import app.wagix.wagixcreditservice.tokens.TokenService;
import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.springsecurity.KeycloakSecurityComponents;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticationProcessingFilter;
import org.keycloak.adapters.springsecurity.filter.KeycloakPreAuthActionsFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity(debug = true)
@Import(KeycloakSpringBootConfigResolver.class)
public class MultiSecurityConfig {



    @Configuration
    @Order(1) //Order is 1 -> First the special case
    public static class CustomAdapter extends WebSecurityConfigurerAdapter {

        @Autowired
        TokenService tokenService;

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .csrf().disable()
                    .requestMatchers().antMatchers("/mandate/**")
                    .and()
                    .authorizeRequests().antMatchers("/mandate/place").permitAll()
                    .anyRequest().authenticated()
                    .and().sessionManagement()
                    .sessionCreationPolicy(STATELESS);

            http.addFilterBefore(new TokenAuthenticationFilter(tokenService), UsernamePasswordAuthenticationFilter.class);

//
//            http.csrf().disable();
//            http.sessionManagement().sessionCreationPolicy(STATELESS);
//            http.httpBasic().disable();
//            http.addFilterBefore(new TokenAuthenticationFilter(tokenService),
//                    UsernamePasswordAuthenticationFilter.class)
//                    .authorizeRequests()
//                    .antMatchers("/mandate/**").authenticated();
        }

        //2a6ad1e2efae7882a134361428dcf
    }

    @Configuration
    @ComponentScan(basePackageClasses = KeycloakSecurityComponents.class)
    //no Order, will be configured last => All other urls should go through the keycloak adapter
    public static class KeycloakAdapter extends KeycloakWebSecurityConfigurerAdapter {

        @Autowired
        public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
            KeycloakAuthenticationProvider keycloakAuthenticationProvider = new KeycloakAuthenticationProvider();
            keycloakAuthenticationProvider.setGrantedAuthoritiesMapper(new SimpleAuthorityMapper());
            auth.authenticationProvider(keycloakAuthenticationProvider);
        }

        @Bean
        @Override
        protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
            return new NullAuthenticatedSessionStrategy();
        }

//         necessary due to http://www.keycloak.org/docs/latest/securing_apps/index.html#avoid-double-filter-bean-registration
        @Bean
        public FilterRegistrationBean keycloakAuthenticationProcessingFilterRegistrationBean(KeycloakAuthenticationProcessingFilter filter) {
            FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
            registrationBean.setEnabled(false);
            return registrationBean;
        }
        // necessary due to http://www.keycloak.org/docs/latest/securing_apps/index.html#avoid-double-filter-bean-registration
        @Bean
        public FilterRegistrationBean keycloakPreAuthActionsFilterRegistrationBean(KeycloakPreAuthActionsFilter filter) {
            FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
            registrationBean.setEnabled(false);
            return registrationBean;
        }


        @Override
        protected void configure(HttpSecurity http) throws Exception {
            super.configure(http);

            http
                    .csrf().disable()
                    .authorizeRequests()
                    .anyRequest().authenticated();
        }

    }
}
