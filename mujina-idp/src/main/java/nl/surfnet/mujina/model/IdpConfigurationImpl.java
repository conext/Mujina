/*
 * Copyright 2012 SURFnet bv, The Netherlands
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package nl.surfnet.mujina.model;

import java.security.KeyStore;
import java.util.*;

import com.google.common.collect.Maps;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;

import nl.surfnet.spring.security.opensaml.util.KeyStoreUtil;

public class IdpConfigurationImpl extends CommonConfigurationImpl implements IdpConfiguration {

    private final static Logger LOGGER = LoggerFactory.getLogger(IdpConfigurationImpl.class);

    private Map<String,Map<String, String>> attributeMap = new HashMap<String,Map<String, String>>();
    private Collection<SimpleAuthentication> users = new ArrayList<SimpleAuthentication>();
    private AuthenticationMethod.Method authMethod;

    public IdpConfigurationImpl() {
        reset();
    }

    @Override
    public void reset() {
        authMethod = AuthenticationMethod.Method.USER;
        entityId = "http://mock-idp";

        try {
            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null, keystorePassword.toCharArray());
            KeyStoreUtil.appendKeyToKeyStore(keyStore, "http://mock-idp", new ClassPathResource("idp-crt.pem").getInputStream(), new ClassPathResource("idp-key.pkcs8.der").getInputStream(), keystorePassword.toCharArray());
            privateKeyPasswords.put("http://mock-idp", keystorePassword);
        } catch (Exception e) {
            LOGGER.error("Unable to create default keystore", e);
        }

        users.clear();
        attributeMap.clear();

        // Admin
        Map<String, String> userAttributeMap = Maps.newTreeMap();
        userAttributeMap.put("urn:mace:dir:attribute-def:uid", "admin");
        userAttributeMap.put("urn:mace:dir:attribute-def:cn", "Admin Doe");
        userAttributeMap.put("urn:mace:dir:attribute-def:givenName", "Admin");
        userAttributeMap.put("urn:mace:dir:attribute-def:sn", "Doe");
        userAttributeMap.put("urn:mace:dir:attribute-def:displayName", "Admin Doe");
        userAttributeMap.put("urn:mace:dir:attribute-def:mail", "admin.doe@example.com");
        userAttributeMap.put("urn:mace:terena.org:attribute-def:schacHomeOrganization", "example.com");
        userAttributeMap.put("urn:mace:dir:attribute-def:eduPersonPrincipalName", "admin.doe@example.com");
        userAttributeMap.put("urn:oid:1.3.6.1.4.1.1076.20.100.10.10.1", "guest");

        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new GrantedAuthorityImpl("ROLE_USER"));
        authorities.add(new GrantedAuthorityImpl("ROLE_ADMIN"));
        final SimpleAuthentication admin = new SimpleAuthentication("admin", "secret", authorities);
        users.add(admin);
        attributeMap.put(admin.getName(), userAttributeMap);

        // john.doe
        userAttributeMap = Maps.newTreeMap();
        userAttributeMap.put("urn:mace:dir:attribute-def:uid", "john.doe");
        userAttributeMap.put("urn:mace:dir:attribute-def:cn", "John Doe");
        userAttributeMap.put("urn:mace:dir:attribute-def:givenName", "John");
        userAttributeMap.put("urn:mace:dir:attribute-def:sn", "Doe");
        userAttributeMap.put("urn:mace:dir:attribute-def:displayName", "John Doe");
        userAttributeMap.put("urn:mace:dir:attribute-def:mail", "j.doe@example.com");
        userAttributeMap.put("urn:mace:terena.org:attribute-def:schacHomeOrganization", "example.com");
        userAttributeMap.put("urn:mace:dir:attribute-def:eduPersonPrincipalName", "j.doe@example.com");
        userAttributeMap.put("urn:oid:1.3.6.1.4.1.1076.20.100.10.10.1", "guest");

        authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new GrantedAuthorityImpl("ROLE_USER"));
        final SimpleAuthentication user = new SimpleAuthentication("john.doe", "secret", authorities);
        users.add(user);
        attributeMap.put(user.getName(), userAttributeMap);


        // user
        userAttributeMap = Maps.newTreeMap();
        userAttributeMap.put("urn:mace:dir:attribute-def:uid", "tom.smith");
        userAttributeMap.put("urn:mace:dir:attribute-def:cn", "Tom Smith");
        userAttributeMap.put("urn:mace:dir:attribute-def:givenName", "Tom");
        userAttributeMap.put("urn:mace:dir:attribute-def:sn", "Smith");
        userAttributeMap.put("urn:mace:dir:attribute-def:displayName", "Tom Smith");
        userAttributeMap.put("urn:mace:dir:attribute-def:mail", "tom.smith@example.com");
        userAttributeMap.put("urn:mace:terena.org:attribute-def:schacHomeOrganization", "example.com");
        userAttributeMap.put("urn:mace:dir:attribute-def:eduPersonPrincipalName", "tom.smith@example.com");
        userAttributeMap.put("urn:oid:1.3.6.1.4.1.1076.20.100.10.10.1", "guest");
        authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new GrantedAuthorityImpl("ROLE_USER"));
        final SimpleAuthentication user2 = new SimpleAuthentication("user", "secret", authorities);
        attributeMap.put(user2.getName(), userAttributeMap);
        users.add(user2);



        setSigning(false);
    }

    @Override
    public Map<String, Map<String, String>> getAttributeMap() {
        return attributeMap;
    }

    @Override
    public Collection<SimpleAuthentication> getUsers() {
        return users;
    }

    @Override
    public AuthenticationMethod.Method getAuthentication() {
        return authMethod;
    }

    @Override
    public void setAuthentication(final AuthenticationMethod.Method method) {
        this.authMethod = method;
    }

    @Override
    public Map<String, String> createAttributeMap(String user) {
        Map<String, String> userAttributeMap = Maps.newTreeMap();
        userAttributeMap.put("urn:mace:dir:attribute-def:uid", user);
        userAttributeMap.put("urn:mace:dir:attribute-def:cn", user);
        userAttributeMap.put("urn:mace:dir:attribute-def:givenName", user);
        userAttributeMap.put("urn:mace:dir:attribute-def:sn", user);
        userAttributeMap.put("urn:mace:dir:attribute-def:displayName", user);
        userAttributeMap.put("urn:mace:dir:attribute-def:mail", user + "@example.com");
        userAttributeMap.put("urn:mace:terena.org:attribute-def:schacHomeOrganization", "example.com");
        userAttributeMap.put("urn:mace:dir:attribute-def:eduPersonPrincipalName", user + "@example.com");
        userAttributeMap.put("urn:oid:1.3.6.1.4.1.1076.20.100.10.10.1", "guest");
        return userAttributeMap;
    }

}
