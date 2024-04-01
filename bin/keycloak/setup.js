const KEYCLOAK_ADMIN = process.env.KEYCLOAK_ADMIN ?? 'admin';
const KEYCLOAK_ADMIN_PASSWORD = process.env.KEYCLOAK_ADMIN_PASSWORD ?? 'admin';
const KEYCLOAK_SERVER = process.env.KEYCLOAK_SERVER ?? 'http://localhost:8080';
const KEYCLOAK_REALM = process.env.KEYCLOAK_REALM ?? 'test';
const KEYCLOAK_IDENTITY_PROVIDER =
  process.env.KEYCLOAK_IDENTITY_PROVIDER ?? 'singpass';
const KEYCLOAK_IDENTITY_PROVIDER_NAME =
  process.env.KEYCLOAK_IDENTITY_PROVIDER_NAME ?? 'Singpass';
const KEYCLOAK_CLIENT =
  process.env.KEYCLOAK_CLIENT ?? 'mockpass-spring-boot-example';

const credentials = async ({ server, user, password }) => {
  const response = await fetch(
    `${server}/realms/master/protocol/openid-connect/token`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        username: user,
        password,
        grant_type: 'password',
        client_id: 'admin-cli',
      }),
    }
  );
  const token = await response.json();
  if (token.error_description) {
    throw new Error(token.error_description);
  }
  return token.access_token;
};

const setup = async () => {
  const bearer = await credentials({
    server: KEYCLOAK_SERVER,
    user: KEYCLOAK_ADMIN,
    password: KEYCLOAK_ADMIN_PASSWORD,
  });
  const headers = {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${bearer}`,
  };
  // Create realm
  console.info(`Creating realm '${KEYCLOAK_REALM}'`);
  let response = await fetch(`${KEYCLOAK_SERVER}/admin/realms`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      enabled: true,
      realm: KEYCLOAK_REALM,
      registrationAllowed: true,
    }),
  });
  let json = null;
  if (response.status !== 201) {
    json = await response.json();
    console.error(
      `Failed to create realm '${KEYCLOAK_REALM}': ${json.errorMessage}`
    );
  } else {
    console.info(`Created realm '${KEYCLOAK_REALM}'`);
  }
  // Create identity provider
  console.info(`Creating identity provider '${KEYCLOAK_IDENTITY_PROVIDER}'`);
  response = await fetch(
    `${KEYCLOAK_SERVER}/admin/realms/${KEYCLOAK_REALM}/identity-provider/instances`,
    {
      method: 'POST',
      headers,
      body: JSON.stringify({
        alias: KEYCLOAK_IDENTITY_PROVIDER,
        config: {
          authorizationUrl: 'http://localhost:5156/singpass/v2/authorize',
          clientAssertionAudience: 'http://localhost:5156/singpass/v2',
          clientAssertionSigningAlg: 'ES256',
          clientAuthMethod: 'private_key_jwt',
          clientId: 'keycloak-client',
          clientSecret: '',
          guiOrder: '',
          issuer: 'http://localhost:5156/singpass/v2',
          jwksUrl: 'http://localhost:5156/singpass/v2/.well-known/keys',
          jwtX509HeadersEnabled: 'false',
          logoutUrl: '',
          metadataDescriptorUrl:
            'http://localhost:5156/singpass/v2/.well-known/openid-configuration',
          pkceEnabled: 'false',
          tokenUrl: 'http://localhost:5156/singpass/v2/token',
          useJwksUrl: 'true',
          userInfoUrl: '',
          validateSignature: 'true',
        },
        displayName: KEYCLOAK_IDENTITY_PROVIDER_NAME,
        providerId: 'oidc',
      }),
    }
  );
  if (response.status !== 201) {
    json = await response.json();
    console.error(
      `Failed to create identity provider '${KEYCLOAK_IDENTITY_PROVIDER}': ${json.errorMessage}`
    );
  } else {
    console.info(`Created identity provider '${KEYCLOAK_IDENTITY_PROVIDER}'`);
  }
  // Create key provider
  console.info(`Creating key provider 'rsa-oaep-256-enc-generated'`);
  response = await fetch(
    `${KEYCLOAK_SERVER}/admin/realms/${KEYCLOAK_REALM}/components`,
    {
      method: 'POST',
      headers,
      body: JSON.stringify({
        name: 'rsa-oaep-256-enc-generated',
        config: {
          priority: ['0'],
          enabled: ['true'],
          active: ['true'],
          keySize: ['2048'],
          algorithm: ['RSA-OAEP-256'],
        },
        providerId: 'rsa-enc-generated',
        providerType: 'org.keycloak.keys.KeyProvider',
      }),
    }
  );
  if (response.status !== 201) {
    json = await response.json();
    console.error(
      `Failed to create key provider 'rsa-oaep-256-enc-generated': ${json.errorMessage}`
    );
  } else {
    console.info(`Created key provider 'rsa-oaep-256-enc-generated'`);
  }
  console.info(`Creating key provider 'ecdsa-generated'`);
  response = await fetch(
    `${KEYCLOAK_SERVER}/admin/realms/${KEYCLOAK_REALM}/components`,
    {
      method: 'POST',
      headers,
      body: JSON.stringify({
        name: 'ecdsa-generated',
        config: {
          priority: ['0'],
          enabled: ['true'],
          active: ['true'],
          ecdsaEllipticCurveKey: ['P-256'],
        },
        providerId: 'ecdsa-generated',
        providerType: 'org.keycloak.keys.KeyProvider',
      }),
    }
  );
  if (response.status !== 201) {
    json = await response.json();
    console.error(
      `Failed to create key provider 'ecdsa-generated': ${json.errorMessage}`
    );
  } else {
    console.info(`Created key provider 'ecdsa-generated'`);
  }
  // Configure First Broker Login
  response = await fetch(
    `${KEYCLOAK_SERVER}/admin/realms/${KEYCLOAK_REALM}/authentication/flows/first%20broker%20login/executions`,
    {
      method: 'GET',
      headers,
    }
  );
  if (response.status !== 200) {
    json = await response.json();
    console.error(
      `Failed to get authentication flow 'first broker login': ${json.errorMessage}`
    );
  } else {
    json = await response.json();
    const id = json[0].authenticationConfig;
    console.info(`Configuring authentication flow 'first broker login'`);
    response = await fetch(
      `${KEYCLOAK_SERVER}/admin/realms/${KEYCLOAK_REALM}/authentication/config/${id}`,
      {
        method: 'PUT',
        headers,
        body: JSON.stringify({
          id,
          alias: 'review profile config',
          config: {
            'update.profile.on.first.login': 'off',
          },
        }),
      }
    );
    if (response.status !== 204) {
      json = await response.json();
      console.error(
        `Failed to configure authentication flow 'first broker login' Review Profile config: ${json.errorMessage}`
      );
    } else {
      console.info(
        `Configured authentication flow 'first broker login' Review Profile config`
      );
    }
    const body = { ...json[0], requirement: 'DISABLED' };
    response = await fetch(
      `${KEYCLOAK_SERVER}/admin/realms/${KEYCLOAK_REALM}/authentication/flows/first%20broker%20login/executions`,
      {
        method: 'PUT',
        headers,
        body: JSON.stringify(body),
      }
    );
    if (response.status !== 202) {
      json = await response.json();
      console.error(
        `Failed to configure authentication flow 'first broker login' to disable Review Profile: ${json.errorMessage}`
      );
    } else {
      console.info(
        `Configured authentication flow 'first broker login' to disable Review Profile`
      );
    }
  }
  // Configure Users Profile
  response = await fetch(
    `${KEYCLOAK_SERVER}/admin/realms/${KEYCLOAK_REALM}/users/profile`,
    {
      method: 'GET',
      headers,
    }
  );
  if (response.status !== 200) {
    json = await response.json();
    console.error(`Failed to get 'users profile': ${json.errorMessage}`);
  } else {
    json = await response.json();
    let body = { ...json };
    delete body.attributes[1].required;
    delete body.attributes[2].required;
    delete body.attributes[3].required;
    response = await fetch(
      `${KEYCLOAK_SERVER}/admin/realms/${KEYCLOAK_REALM}/users/profile`,
      {
        method: 'PUT',
        headers,
        body: JSON.stringify(body),
      }
    );
    if (response.status !== 200) {
      json = await response.json();
      console.error(
        `Failed to configure 'users profile': ${json.errorMessage}`
      );
    } else {
      console.info(`Configured 'users profile'`);
    }
  }
  // Create client
  console.info(`Creating client '${KEYCLOAK_CLIENT}'`);
  response = await fetch(
    `${KEYCLOAK_SERVER}/admin/realms/${KEYCLOAK_REALM}/clients`,
    {
      method: 'POST',
      headers,
      body: JSON.stringify({
        attributes: {
          'access.token.signed.response.alg': 'ES256',
          'backchannel.logout.revoke.offline.tokens': 'false',
          'backchannel.logout.session.required': 'true',
          'backchannel.logout.url':
            'http://localhost:8081/logout/connect/back-channel/mockpass',
          'id.token.signed.response.alg': 'ES256',
          'jwks.url': 'http://localhost:8081/oauth2/jwks',
          'post.logout.redirect.uris': 'http://localhost:8081/*',
          'use.jwks.url': 'true',
        },
        clientAuthenticatorType: 'client-jwt',
        clientId: KEYCLOAK_CLIENT,
        description: '',
        directAccessGrantsEnabled: false,
        frontchannelLogout: false,
        name: '',
        protocol: 'openid-connect',
        publicClient: false,
        redirectUris: ['http://localhost:8081/*'],
        rootUrl: '',
        serviceAccountsEnabled: false,
        standardFlowEnabled: true,
        webOrigins: ['http://localhost:8081/*'],
      }),
    }
  );
  if (response.status !== 201) {
    json = await response.json();
    console.error(
      `Failed to create client '${KEYCLOAK_CLIENT}': ${json.errorMessage}`
    );
  } else {
    console.info(`Created client '${KEYCLOAK_CLIENT}'`);
  }
};

setup()
  .catch((err) => console.error(err.message ?? err))
  .finally(() => console.info('Setup complete'));
