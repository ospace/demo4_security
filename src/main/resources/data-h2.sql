INSERT INTO authorities (username, authority) VALUES ('foo', 'USER');
INSERT INTO authorities (username, authority) VALUES ('admin', 'ADMIN');

-- USER
-- non-encrypted password: jwtpass
INSERT INTO _users (username, password, enabled) VALUES ('foo', '$2a$10$qtH0F1m488673KwgAfFXEOWxsoZSeHqqlB/8BTt3a6gsI5c2mdlfe', true);
INSERT INTO _users (username, password, enabled) VALUES ('admin', '$2a$10$qtH0F1m488673KwgAfFXEOWxsoZSeHqqlB/8BTt3a6gsI5c2mdlfe', true);

-- INSERT INTO user_role(user_id, role_id) VALUES(1,1);
-- INSERT INTO user_role(user_id, role_id) VALUES(2,1);
-- INSERT INTO user_role(user_id, role_id) VALUES(2,2);

-- insert client details
INSERT INTO oauth_client_details
   (client_id, client_secret, scope, authorized_grant_types,
   authorities, access_token_validity, refresh_token_validity)
VALUES
   ('testjwtclientid', 'XY7kmzoNzl100', 'read,write', 'password,refresh_token,client_credentials,authorization_code',
   'ROLE_CLIENT,ROLE_TRUSTED_CLIENT', 900, 2592000);