package akka.http.spring.oauth2.demo;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.approval.TokenStoreUserApprovalHandler;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenGranter;
import org.springframework.security.oauth2.provider.client.ClientDetailsUserDetailsService;
import org.springframework.security.oauth2.provider.client.InMemoryClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeTokenGranter;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;
import org.springframework.security.oauth2.provider.implicit.ImplicitTokenGranter;
import org.springframework.security.oauth2.provider.password.ResourceOwnerPasswordTokenGranter;
import org.springframework.security.oauth2.provider.refresh.RefreshTokenGranter;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;

@Configuration
public class OAuth2ServerConfig {

	@Bean
	public ClientDetailsService clientDetailsService() {
		InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
		BaseClientDetails clientDetails = new BaseClientDetails();
		clientDetails.setClientId("client_id");
		clientDetails.setClientSecret("client_secret");
		clientDetails.setAuthorizedGrantTypes(Arrays.asList("password", "client_credentials"));
		clientDetails.setAuthorities(Collections.singleton(new SimpleGrantedAuthority("write_doc")));
		Map<String, ? extends ClientDetails> clientDetailsStore = Collections.singletonMap(clientDetails.getClientId(),
				clientDetails);
		clientDetailsService.setClientDetailsStore(clientDetailsStore);
		return clientDetailsService;
	}

	@Bean
	public UserDetailsManager userDetailsManager() {
		User user = new User("username", "password", Collections.singleton(new SimpleGrantedAuthority("some")));
		return new InMemoryUserDetailsManager(Collections.singleton(user));
	}
	
	@Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter() {
		return new JwtAccessTokenConverter();
	}

	@Bean
	public TokenStore tokenStore(JwtAccessTokenConverter jwtAccessTokenConverter) {
		return new JwtTokenStore(jwtAccessTokenConverter);
	}

	@Bean
	public AuthorizationCodeServices authorizationCodeServices() {
		return new InMemoryAuthorizationCodeServices();
	}

	@Bean
	public ClientDetailsUserDetailsService clientDetailsUserDetailsService(ClientDetailsService clientDetailsService) {
		return new ClientDetailsUserDetailsService(clientDetailsService);
	}

	@Bean(name = "clientAuthenticationProvider")
	public DaoAuthenticationProvider clientAuthenticationProvider(
			ClientDetailsUserDetailsService clientDetailsService) {
		DaoAuthenticationProvider clientAuthenticationProvider = new DaoAuthenticationProvider();
		clientAuthenticationProvider.setUserDetailsService(clientDetailsService);
		return clientAuthenticationProvider;
	}

	@Bean(name = "clientAuthenticationManager")
	public AuthenticationManager clientAuthenticationManager(
			@Qualifier("clientAuthenticationProvider") AuthenticationProvider clientAuthenticationProvider) {
		return new ProviderManager(Arrays.asList(clientAuthenticationProvider));
	}

	@Bean(name = "userAuthenticationProvider")
	public DaoAuthenticationProvider userAuthenticationProvider(UserDetailsManager userDetailsManager) {
		DaoAuthenticationProvider userAuthenticationProvider = new DaoAuthenticationProvider();
		userAuthenticationProvider.setUserDetailsService(userDetailsManager);
		return userAuthenticationProvider;
	}

	@Bean(name = "userAuthenticationManager")
	public AuthenticationManager userAuthenticationManager(
			@Qualifier("userAuthenticationProvider") AuthenticationProvider userAuthenticationProvider) {
		return new ProviderManager(Arrays.asList(userAuthenticationProvider));
	}

	@Bean
	public OAuth2RequestFactory oAuth2RequestFactory(ClientDetailsService clientDetailsService) {
		return new DefaultOAuth2RequestFactory(clientDetailsService);
	}

	@Bean(name = "oAuth2AuthenticationManager")
	public AuthenticationManager authenticationManager(ResourceServerTokenServices tokenServices) {
		OAuth2AuthenticationManager authenticationManager = new OAuth2AuthenticationManager();
		authenticationManager.setTokenServices(tokenServices);
		return authenticationManager;
	}

	@Bean
	public DefaultTokenServices tokenService(TokenStore tokenStore, ClientDetailsService clientDetailsService, JwtAccessTokenConverter jwtAccessTokenConverter) {
		DefaultTokenServices tokenServices = new DefaultTokenServices();
		tokenServices.setTokenStore(tokenStore);
		tokenServices.setClientDetailsService(clientDetailsService);
		tokenServices.setTokenEnhancer(jwtAccessTokenConverter);
		return tokenServices;
	}

	@Bean
	public TokenGranter tokenGranter(
			@Qualifier("userAuthenticationManager") AuthenticationManager userAuthenticationManager,
			AuthorizationServerTokenServices tokenServices, ClientDetailsService clientDetailsService,
			OAuth2RequestFactory requestFactory, AuthorizationCodeServices authorizationCodeServices) {
		ClientCredentialsTokenGranter clientCredentialsTokenGranter = new ClientCredentialsTokenGranter(tokenServices,
				clientDetailsService, requestFactory);
		ResourceOwnerPasswordTokenGranter resourceOwnerPasswordTokenGranter = new ResourceOwnerPasswordTokenGranter(
				userAuthenticationManager, tokenServices, clientDetailsService, requestFactory);
		AuthorizationCodeTokenGranter authorizationCodeTokenGranter = new AuthorizationCodeTokenGranter(tokenServices,
				authorizationCodeServices, clientDetailsService, requestFactory);
		ImplicitTokenGranter implicitTokenGranter = new ImplicitTokenGranter(tokenServices, clientDetailsService,
				requestFactory);
		RefreshTokenGranter refreshTokenGranter = new RefreshTokenGranter(tokenServices, clientDetailsService,
				requestFactory);
		return new CompositeTokenGranter(Arrays.asList(clientCredentialsTokenGranter, resourceOwnerPasswordTokenGranter,
				authorizationCodeTokenGranter, implicitTokenGranter, refreshTokenGranter));
	}

	@Bean
	public UserApprovalHandler userApprovalHandler(TokenStore tokenStore, OAuth2RequestFactory requestFactory,
			ClientDetailsService clientDetailsService) {
		TokenStoreUserApprovalHandler tokenStoreUserApprovalHandler = new TokenStoreUserApprovalHandler();
		tokenStoreUserApprovalHandler.setTokenStore(tokenStore);
		tokenStoreUserApprovalHandler.setRequestFactory(requestFactory);
		tokenStoreUserApprovalHandler.setClientDetailsService(clientDetailsService);
		return tokenStoreUserApprovalHandler;
	}

	@Bean
	public TokenEndpoint tokenEndpoint(TokenGranter tokenGranter, ClientDetailsService clientDetailsService) {
		TokenEndpoint tokenEndpoint = new TokenEndpoint();
		tokenEndpoint.setTokenGranter(tokenGranter);
		tokenEndpoint.setClientDetailsService(clientDetailsService);
		return tokenEndpoint;
	}

	@Bean
	public AuthorizationEndpoint authorizationEndpoint(TokenGranter tokenGranter,
			ClientDetailsService clientDetailsService, AuthorizationCodeServices authorizationCodeServices,
			UserApprovalHandler userApprovalHandler) {
		AuthorizationEndpoint authorizationEndpoint = new AuthorizationEndpoint();
		authorizationEndpoint.setTokenGranter(tokenGranter);
		authorizationEndpoint.setClientDetailsService(clientDetailsService);
		authorizationEndpoint.setAuthorizationCodeServices(authorizationCodeServices);
		authorizationEndpoint.setUserApprovalHandler(userApprovalHandler);
		return authorizationEndpoint;
	}

}
