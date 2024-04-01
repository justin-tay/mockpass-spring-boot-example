# Spring Boot Example OpenID Connect Relying Party for Singpass/Corppass

This project is an example implementation of a OpenID Connect Relying Party built using Spring Boot and Spring Security OAuth2 Client.

[Keycloak](https://github.com/keycloak/keycloak) is used as the Identity Provider to broker to Mockpass for testing purposes
[MockPass](https://github.com/opengovsg/mockpass) is used as the public Identity Provider for testing purposes

## Quick Start

### Configuring MockPass as the Identity Provider for Keycloak

```shell
set SHOW_LOGIN_PAGE=true
set SP_RP_JWKS_ENDPOINT=http://localhost:8080/realms/test/protocol/openid-connect/certs
set CP_RP_JWKS_ENDPOINT=http://localhost:8080/realms/test/protocol/openid-connect/certs
npx --y @opengovsg/mockpass
```

### Installing and running the Relying Party Spring Boot application

```shell
mvn spring-boot:run -Dspring-boot.run.profiles=keycloak
```

### Testing the example Relying Party


| Description                        | Endpoint
|------------------------------------|-----------------------------------------------------
| Access the application             | http://localhost:8081/login-user
| Logout from the application        | http://localhost:8081/logout
| View the public keys               | http://localhost:8081/oauth2/jwks
| View Mockpass public keys          | http://localhost:5156/singpass/v2/.well-known/keys
| View Mockpass OpenID configuration | http://localhost:5156/singpass/v2/.well-known/openid-configuration
