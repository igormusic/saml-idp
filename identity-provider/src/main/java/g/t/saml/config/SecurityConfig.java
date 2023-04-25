package g.t.saml.config;

import org.apache.catalina.filters.CorsFilter;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.provider.identity.config.SamlIdentityProviderSecurityConfiguration;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.session.SessionManagementFilter;

import static org.springframework.security.saml.provider.identity.config.SamlIdentityProviderSecurityDsl.identityProvider;

@EnableWebSecurity
public class SecurityConfig {

    @Configuration
    @Order(1)
    public static class SamlSecurity extends SamlIdentityProviderSecurityConfiguration {

        private final AppProperties appProperties;
        private final SAMLConfig samlConfig;

        public SamlSecurity(SAMLConfig samlConfig, @Qualifier("appProperties") AppProperties appProperties) {
            super("/saml/idp/", samlConfig);
            this.appProperties = appProperties;
            this.samlConfig = samlConfig;
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            super.configure(http);
            http.
                    userDetailsService(samlConfig.userDetailsService())
                    .formLogin();

            http.
                    apply(identityProvider())
                    .configure(appProperties);
        }
    }

    @Configuration
    public static class AppSecurity extends WebSecurityConfigurerAdapter {

        private final CustomAuthenticationProvider customAuthenticationProvider;
        private final SAMLConfig samlConfig;

        public AppSecurity(CustomAuthenticationProvider customAuthenticationProvider, SAMLConfig samlConfig) {
            this.customAuthenticationProvider = customAuthenticationProvider;
            this.samlConfig = samlConfig;
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .antMatcher("/**")
                    .authorizeRequests()
                    .antMatchers("/**").authenticated()
                    .and()
                    .cors().disable()
                    .addFilterBefore(new HeaderAuthenticationFilter(), SessionManagementFilter.class)
                    .sessionManagement();


        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.authenticationProvider(customAuthenticationProvider);
        }
    }


}