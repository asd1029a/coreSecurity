//package io.security.corespringsecurity.security.configs;
//
//import io.security.corespringsecurity.filter.AjaxLoginProcessingFilter;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
//import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
//import org.springframework.security.web.authentication.AuthenticationFailureHandler;
//import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
//import org.springframework.security.web.util.matcher.RequestMatcher;
//
//public class AjaxLoginConfigurer<H extends HttpSecurityBuilder<H>> extends AbstractAuthenticationFilterConfigurer<H, AjaxLoginConfigurer<H>, AjaxLoginProcessingFilter> {
//
//    private AuthenticationSuccessHandler authenticationSuccessHandler;
//    private AuthenticationFailureHandler failureHandler;
//    private AuthenticationManager authenticationManager;
//
//    @Override
//    protected RequestMatcher createLoginProcessingUrlMatcher(String s) {
//        return null;
//    }
//
//    public AjaxLoginConfigurer() {
//
//    }
//}
