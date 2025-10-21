package com.mesaverde.conf;

import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.Resource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
@Import(OAuth2AuthorizationServerConfiguration.class)
public class AuthorizationServerConf {

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    JWKSource<SecurityContext> jwkSource(
            @Value("${app.keystore.path}") Resource keystorePath,
            @Value("${app.keystore.password}") String keyStorePassword,
            @Value("${app.keystore.alias}") String alias)
            throws Exception {

        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream is = keystorePath.getInputStream()) {
            ks.load(is, keyStorePassword.toCharArray());
        }

        Key key = ks.getKey(alias, keyStorePassword.toCharArray());
        if (!(key instanceof PrivateKey)) {
            throw new IllegalStateException("The key with alias '" + alias + "' is not a private key.");
        }

        Certificate cert = ks.getCertificate(alias);
        RSAPublicKey publicKey = (RSAPublicKey) cert.getPublicKey();
        RSAPrivateKey privateKey = (RSAPrivateKey) key;

        RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()) // opcional .keyID(alias) establece un id fijo
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }



    @Bean
    AuthenticationManager authenticationManager(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);

        return new ProviderManager(provider);
    }

    @Bean
    RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("my-client")
                .clientSecret(passwordEncoder.encode("my-secret"))
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("read")
                .scope("write")
                .build();

        return new InMemoryRegisteredClientRepository(client);
    }


    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            Authentication principal = context.getPrincipal();
            if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN) && principal.getAuthorities() != null) {

                context.getClaims().claim("roles", principal.getAuthorities().stream().map(a -> a.getAuthority()).toList()); //GrantedAuthority::getAuthority).toList());

                Object principalObj = principal.getPrincipal();
                if (principalObj instanceof CustomUserDetails userDetails) {
                    context.getClaims().claim("username", userDetails.getUsername());
                    context.getClaims().claim("email", userDetails.getEmail());
                }
            }
        };
    }

}




 /*
  * @Bean RegisteredClientRepository registeredClientRepository(JdbcTemplate
			  jdbcTemplate) { RegisteredClient registeredClient =
			  RegisteredClient.withId(UUID.randomUUID().toString()) .clientId("my-client")
			  // ID público del cliente .clientSecret("secret") // Contraseña
			  .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
			  .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			  .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
			  .redirectUri("http://127.0.0.1:8080/login/oauth2/code/my-client-oidc")
			  .scope(OidcScopes.OPENID) .scope("read")
			  .clientSettings(ClientSettings.builder() .requireAuthorizationConsent(true)
			  // Pide consentimiento .build()) .tokenSettings(TokenSettings.builder()
			  .accessTokenTimeToLive(Duration.ofHours(1))
			  .refreshTokenTimeToLive(Duration.ofHours(3)) .reuseRefreshTokens(true)
			  .build()) .build();

			  JdbcRegisteredClientRepository repository = new
			  JdbcRegisteredClientRepository(jdbcTemplate); // Guardar el cliente si no
			  existe if (repository.findByClientId("my-client") == null) {
			  repository.save(registeredClient); }

			  return repository; }
*/


/*Metodo anterior sin constructor en DaoAuthenticationProvider
 * @Bean AuthenticationManager authenticationManager(UserDetailsService
 * userDetailsService, PasswordEncoder passwordEncoder){
 * DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
 * provider.setUserDetailsService(userDetailsService);
 * provider.setPasswordEncoder(passwordEncoder);
 *
 * return new ProviderManager(provider); }
 */