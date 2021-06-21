package org.springframework.security.oauth2.provider;

import java.util.Arrays;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.provider.AdminEndpointsTests.ResourceOwnerReadOnly;

public class MyTests {
	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();
	
//	@Rule
//	public OAuth2ContextSetup context = OAuth2ContextSetup.standard(serverRunning);
	
	@Test
	public void testDo(){
		System.out.println("goooooo");
	}

}
