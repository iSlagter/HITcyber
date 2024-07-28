-- יcreate SPs

use communication_ltd_secure;
-- SP add user
DELIMITER //
CREATE PROCEDURE add_user(IN p_username VARCHAR(255), IN p_email VARCHAR(255), IN p_password_hash VARCHAR(255), IN p_salt VARCHAR(255))
BEGIN
    INSERT INTO users (username, email, password_hash, salt) VALUES (p_username, p_email, p_password_hash, p_salt);
    INSERT INTO password_history (user_id, password_hash) VALUES (LAST_INSERT_ID(), p_password_hash);
END //
DELIMITER ;

-- SP if user exist
DELIMITER //
CREATE PROCEDURE get_user_by_username(IN p_username VARCHAR(255))
BEGIN
    SELECT id, password_hash, salt FROM users WHERE username = p_username;
END //
DELIMITER ;

-- SP add customer
DELIMITER //
CREATE PROCEDURE add_customer(IN p_first_name VARCHAR(255), IN p_last_name VARCHAR(255), IN p_address VARCHAR(255))
BEGIN
    INSERT INTO customers (first_name, last_name, address) VALUES (p_first_name, p_last_name, p_address);
END //
DELIMITER ;

-- SP add password to the history
DELIMITER //
CREATE PROCEDURE add_password_history(IN p_user_id INT, IN p_password_hash VARCHAR(255))
BEGIN
    INSERT INTO password_history (user_id, password_hash) VALUES (p_user_id, p_password_hash);
END //
DELIMITER ;

-- SP update password
DELIMITER //
CREATE PROCEDURE update_password(IN p_user_id INT, IN p_password_hash VARCHAR(255))
BEGIN
    UPDATE users SET password_hash = p_password_hash WHERE id = p_user_id;
END //
DELIMITER ;

-- SP get id from email
DELIMITER //
CREATE PROCEDURE get_user_by_email(IN p_email VARCHAR(255))
BEGIN
    SELECT id FROM users WHERE email = p_email;
END //
DELIMITER ;

-- SP save token of reset password
DELIMITER //
CREATE PROCEDURE add_reset_token(IN p_user_id INT, IN p_token VARCHAR(255))
BEGIN
    INSERT INTO reset_tokens (user_id, token) VALUES (p_user_id, p_token);
END //
DELIMITER ;

-- SP check token
DELIMITER //
CREATE PROCEDURE get_user_by_reset_token(IN p_token VARCHAR(255), IN p_email VARCHAR(255))
BEGIN
    SELECT rt.user_id
    FROM reset_tokens rt
    JOIN users u ON rt.user_id = u.id
    WHERE rt.token = p_token AND u.email = p_email;
END //
DELIMITER ;

-- SP get user from ID
DELIMITER //
CREATE PROCEDURE get_user_by_id(IN p_user_id INT)
BEGIN
    SELECT id, password_hash, salt FROM users WHERE id = p_user_id;
END //
DELIMITER ;

-- SP get user from ID
DELIMITER //
CREATE PROCEDURE get_username_by_id(IN p_user_id INT)
BEGIN
    SELECT username FROM users WHERE id = p_user_id;
END //
DELIMITER ;

-- SP get all customers for dashboard
DELIMITER //
CREATE PROCEDURE get_all_customers()
BEGIN
    SELECT first_name, last_name, address FROM customers;
END //
DELIMITER ;

-- SP get password history by userID
DELIMITER //
CREATE PROCEDURE get_password_history(IN p_user_id INT, IN p_limit INT)
BEGIN
    SELECT password_hash FROM password_history WHERE user_id = p_user_id ORDER BY change_date DESC LIMIT p_limit;
END //
DELIMITER ;