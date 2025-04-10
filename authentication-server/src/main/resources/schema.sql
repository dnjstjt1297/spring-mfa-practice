CREATE TABLE IF NOT EXISTS `spring`.`user` (
    `username` VARCHAR(45) NOT NULL,
    `password` TEXT NOT NULL,
    PRIMARY KEY (`username`));

CREATE TABLE IF NOT EXISTS `spring`.`otp` (
    `username` VARCHAR(45) NOT NULL,
    `code` VARCHAR(45) NOT NULL,
    PRIMARY KEY (`username`));

CREATE TABLE IF NOT EXISTS `spring`.`refresh_tokens` (
     `username` VARCHAR(255) PRIMARY KEY,
     `token` VARCHAR(255) NOT NULL UNIQUE,
     `expiry_date` TIMESTAMP NOT NULL);
