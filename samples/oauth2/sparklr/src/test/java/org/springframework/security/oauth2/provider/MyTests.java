package org.springframework.security.oauth2.provider;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.client.resource.UserApprovalRequiredException;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.test.BeforeOAuth2Context;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InsufficientScopeException;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.common.exceptions.UserDeniedAuthorizationException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AdminEndpointsTests.ClientCredentialsReadOnly;
import org.springframework.security.oauth2.provider.AdminEndpointsTests.ResourceOwnerReadOnly;
import org.springframework.security.oauth2.provider.AdminEndpointsTests.ResourceOwnerWriteOnly;
import org.springframework.security.oauth2.provider.AuthorizationCodeProviderTests.MyLessTrustedClient;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.ResponseExtractor;

public class MyTests {
	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();
	
	@Rule
	public OAuth2ContextSetup context = OAuth2ContextSetup.standard(serverRunning);
	
	private AuthorizationCodeAccessTokenProvider accessTokenProvider;

	private ClientHttpResponse tokenEndpointResponse;
	
	@BeforeOAuth2Context
	public void setupAccessTokenProvider() {
		accessTokenProvider = new AuthorizationCodeAccessTokenProvider() {

			private ResponseExtractor<OAuth2AccessToken> extractor = super.getResponseExtractor();

			private ResponseExtractor<ResponseEntity<Void>> authExtractor = super.getAuthorizationResponseExtractor();

			private ResponseErrorHandler errorHandler = super.getResponseErrorHandler();

			@Override
			protected ResponseErrorHandler getResponseErrorHandler() {
				return new DefaultResponseErrorHandler() {
					public void handleError(ClientHttpResponse response) throws IOException {
						response.getHeaders();
						response.getStatusCode();
						tokenEndpointResponse = response;
						errorHandler.handleError(response);
					}
				};
			}

			@Override
			protected ResponseExtractor<OAuth2AccessToken> getResponseExtractor() {
				return new ResponseExtractor<OAuth2AccessToken>() {

					public OAuth2AccessToken extractData(ClientHttpResponse response) throws IOException {
						response.getHeaders();
						response.getStatusCode();
						tokenEndpointResponse = response;
						return extractor.extractData(response);
					}

				};
			}

			@Override
			protected ResponseExtractor<ResponseEntity<Void>> getAuthorizationResponseExtractor() {
				return new ResponseExtractor<ResponseEntity<Void>>() {

					public ResponseEntity<Void> extractData(ClientHttpResponse response) throws IOException {
						response.getHeaders();
						response.getStatusCode();
						tokenEndpointResponse = response;
						return authExtractor.extractData(response);
					}
				};
			}
		};
		context.setAccessTokenProvider(accessTokenProvider);
	}
	
	@Test
	public void testResourceIsProtected() throws Exception {
		// first make sure the resource is actually protected.
		assertEquals(HttpStatus.UNAUTHORIZED, serverRunning.getStatusCode("/sparklr2/photos?format=json"));
	}
	
	@Test
//	@OAuth2ContextConfiguration(resource = MyLessTrustedClient2.class, initialize = true)
	@OAuth2ContextConfiguration(resource = MyLessTrustedClient2.class, initialize = false)
	public void testUnauthenticatedAuthorizationRequestRedirectsToLogin() throws Exception {
//	public void testUnauthenticatedAuthorizationRequestRedirectsToLogin(){

		System.out.println(">--------------------testUnauthenticatedAuthorizationRequestRedirectsToLogin-------------------------<");
		
		AccessTokenRequest request = context.getAccessTokenRequest();
		request.setCurrentUri("https://anywhere");
		request.add(OAuth2Utils.USER_OAUTH_APPROVAL, "true");
		
//		request.add(OAuth2Utils.REDIRECT_URI, "http://lzq");

		String location = null;

		try {
			String code = accessTokenProvider.obtainAuthorizationCode(context.getResource(), request);
			
			System.err.println(code);
			
			assertNotNull(code);
			fail("Expected UserRedirectRequiredException");
		}
		catch (UserRedirectRequiredException e) {
			System.err.println(e);
			
			location = e.getRedirectUri();
		}
//		catch(Exception e){
//			System.err.println(e);
//		}

		System.err.println(location);
		
		assertNotNull(location);
		assertEquals(serverRunning.getUrl("/sparklr2/login.jsp"), location);

	}
	
//	@Test
//	@OAuth2ContextConfiguration(resource = MyLessTrustedClient2.class, initialize = false)
//	public void testSuccessfulAuthorizationCodeFlow() throws Exception {
//		
//		System.out.println(">--------------------testSuccessfulAuthorizationCodeFlow-------------------------<");
//
//		// Once the request is ready and approved, we can continue with the access token
//		approveAccessTokenGrant("https://anywhere", true);
////		approveAccessTokenGrant("https://www.baidu.com/", true);
//
//		// Finally everything is in place for the grant to happen...
//		assertNotNull(context.getAccessToken());
//
//		AccessTokenRequest request = context.getAccessTokenRequest();
//		assertNotNull(request.getAuthorizationCode());
//		assertEquals(HttpStatus.OK, serverRunning.getStatusCode("/sparklr2/photos?format=json"));
//
//	}
	
	@Test
	@OAuth2ContextConfiguration(resource = MyLessTrustedClient2.class, initialize = false)
	public void testWrongRedirectUri() throws Exception {
		approveAccessTokenGrant("https://anywhere", true);
		AccessTokenRequest request = context.getAccessTokenRequest();
		// The redirect is stored in the preserved state...
		context.getOAuth2ClientContext().setPreservedState(request.getStateKey(), "https://nowhere");
		// Finally everything is in place for the grant to happen...
		try {
			assertNotNull(context.getAccessToken());
			fail("Expected RedirectMismatchException");
		}
		catch (RedirectMismatchException e) {
			// expected
		}
		assertEquals(HttpStatus.BAD_REQUEST, tokenEndpointResponse.getStatusCode());
	}
	
	private void approveAccessTokenGrant(String currentUri, boolean approved) {

		AccessTokenRequest request = context.getAccessTokenRequest();
		AuthorizationCodeResourceDetails resource = (AuthorizationCodeResourceDetails) context.getResource();

		String cookie = loginAndGrabCookie();
		request.setCookie(cookie);
		if (currentUri != null) {
			request.setCurrentUri(currentUri);
		}

		String location = null;

		try {
			System.out.println(context.getAccessToken());
			
			// First try to obtain the access token...
			assertNotNull(context.getAccessToken());
			fail("Expected UserRedirectRequiredException");
		}
		catch (UserRedirectRequiredException e) {
			// Expected and necessary, so that the correct state is set up in the request...
			location = e.getRedirectUri();
			System.out.println(location);
		}

		assertTrue(location.startsWith(resource.getUserAuthorizationUri()));
		assertNull(request.getAuthorizationCode());

		try {
			// Now try again and the token provider will redirect for user approval...
			assertNotNull(context.getAccessToken());
			fail("Expected UserRedirectRequiredException");
		}
		catch (UserApprovalRequiredException e) {
			// Expected and necessary, so that the user can approve the grant...
			location = e.getApprovalUri();
		}

		assertTrue(location.startsWith(resource.getUserAuthorizationUri()));
		assertNull(request.getAuthorizationCode());

		// The approval (will be processed on the next attempt to obtain an access token)...
		request.set(OAuth2Utils.USER_OAUTH_APPROVAL, "" + approved);

	}
	
	private String loginAndGrabCookie() {
//		try {
			ResponseEntity<String> page = serverRunning.getForString("/sparklr2/login.jsp");
			String cookie = page.getHeaders().getFirst("Set-Cookie");
			Matcher matcher = Pattern.compile("(?s).*name=\"_csrf\".*?value=\"([^\"]+).*").matcher(page.getBody());
	
			MultiValueMap<String, String> formData;
			formData = new LinkedMultiValueMap<String, String>();
			formData.add("username", "marissa");
			formData.add("password", "koala");
			if (matcher.matches()) {
				formData.add("_csrf", matcher.group(1));
			}
	
			String location = "/sparklr2/login";
			HttpHeaders headers = new HttpHeaders();
			headers.set("Cookie", cookie);
			headers.setAccept(Arrays.asList(MediaType.TEXT_HTML));
			ResponseEntity<Void> result = serverRunning.postForStatus(location, headers , formData);
			assertEquals(HttpStatus.FOUND, result.getStatusCode());
			cookie = result.getHeaders().getFirst("Set-Cookie");
	
			assertNotNull("Expected cookie in " + result.getHeaders(), cookie);
	
			return cookie;
//		}catch(UserRedirectRequiredException e){
//			System.err.println(e);
//			System.err.println(e.getRedirectUri());			
//		}
//		
//		return null;
	}
	
	static class MyLessTrustedClient2 extends AuthorizationCodeResourceDetails {
		public MyLessTrustedClient2(Object target) {
			super();
			setClientId("my-less-trusted-client");
//			setClientId("tonr");
			setScope(Arrays.asList("read"));
			setId(getClientId());
			MyTests test = (MyTests) target;
			setAccessTokenUri(test.serverRunning.getUrl("/sparklr2/oauth/token"));
			setUserAuthorizationUri(test.serverRunning.getUrl("/sparklr2/oauth/authorize"));
		}
	}

}
