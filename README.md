# Setup Instruction

Clone this repository locally and follow these steps to integrate it with your APIs
1. Inside `MoneyBags-Auth/src/main/resources/application.yaml` change the database URL (Also this authorization server will run on port 9090, so if something else is running on this port close it)

2. Open SQL developer and drop these two tables (if they exists)
```sql
DROP TABLE roles;
DROP TABLE users;
commit;
```

3. Run the Authorization server

4. Create a user by sending the following request
`POST http://localhost:9090/api/users/register`
```JSON   
{
   "username": "test",
   "password": "test",
   "roles": ["CUSTOMER"] // Create users for whatever role your team requires
}
```

5. Open your browser and enter the following url and login with credentials of the user that you created
   http://localhost:9090/oauth2/authorize?response_type=code&client_id=moneybags-client&scope=openid%20profile&redirect_uri=http://localhost:3000/login/redirect

6. Check the "profile" checkbox and click accept

7. You will be redirected to a http://localhost:3000/login/redirect?code=`<Some Code>`. Copy the code in this URL

8. Send a request to
   `POST http://localhost:9090/oauth2/token`
```
BODY (Content-Type: x-www-form-urlencoded)
   grant_type = authorization_code
   code = <CODE THAT YOU COPIED IN PREVIOUS STEP>
   redirect_uri = http://localhost:3000/login/redirect
   client_id = moneybags-client
   client_secret = secret
```

9. You will get an access token that you can use to send request (This token will expire in 5 minutes)
   To get a new access token copy the refresh token that you've received

10. Send another request to
    `POST http://localhost:9090/oauth2/token` 
```
BODY (Content-Type: x-www-form-urlencoded)
    grant_type = refresh_token
    refresh_token = <REFRESH TOKEN THAT YOU COPIED>
    redirect_uri = http://localhost:3000/login/redirect
    client_id = moneybags-client
    client_secret = secret
    You will receive a new pair of Access and Refresh Token
```

11. Open your team's project an in pom.xml click on "Add starters" and add the following dependencies
    `OAuth2 Resource Server`,
    `Spring Security`

12. Add the following config in your application.properties file
    `spring.security.oauth2.resourceserver.jwt.issuer-uri=http://localhost:9090`

13. Add the following class in your project
```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
private Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthConverter() {
var rolesConverter = new JwtGrantedAuthoritiesConverter();
rolesConverter.setAuthoritiesClaimName("roles");
rolesConverter.setAuthorityPrefix("");

        return jwt -> {
            var roles = rolesConverter.convert(jwt);
            return new JwtAuthenticationToken(jwt, roles);
        };
    }

    @Bean
    public SecurityFilterChain api(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/test/test1").hasAuthority("CUSTOMER")
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth -> oauth
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthConverter()))
                );
        return http.build();
    }
}
```

Now all your requests will be authenticated. To restrict a certain endpoint for a particular role
change and add this line
`requestMatchers(HttpMethod.GET, "/api/test/test1").hasAuthority("CUSTOMER")`
modify it according to your project and make sure the authorization server is always running on port 9090