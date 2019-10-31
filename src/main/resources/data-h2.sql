INSERT INTO authorities (username, authority) VALUES ('foo', 'USER');
INSERT INTO authorities (username, authority) VALUES ('admin', 'ADMIN');

-- USER
-- non-encrypted password: 111
INSERT INTO _users (username, password, enabled) VALUES ('foo', '$2a$10$wC5amRpylfp8Rvb.sAxMJOVaqEpBjv8u5eFloSZoInJWjF0a.K0Vm', true);
INSERT INTO _users (username, password, enabled) VALUES ('admin', '$2a$10$wC5amRpylfp8Rvb.sAxMJOVaqEpBjv8u5eFloSZoInJWjF0a.K0Vm', true);

-- INSERT INTO user_role(user_id, role_id) VALUES(1,1);
-- INSERT INTO user_role(user_id, role_id) VALUES(2,1);
-- INSERT INTO user_role(user_id, role_id) VALUES(2,2);

-- insert client details
-- non-encrypted password: 222
INSERT INTO oauth_client_details
   (client_id, client_secret, scope, authorized_grant_types,
   authorities, access_token_validity, refresh_token_validity)
VALUES
   ('testclient', '$2a$10$r9lBO9ztiEuy8JTCu4IBwugE4mxWsIaSh9qyIoe0sIShkQIaLjfBu', 'read,write', 'password,refresh_token,client_credentials,authorization_code',
   'ROLE_CLIENT,ROLE_TRUSTED_CLIENT', 900, 2592000);