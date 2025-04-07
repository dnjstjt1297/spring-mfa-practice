CREATE TABLE IF NOT EXISTS `spring`.`user` (
    `username` VARCHAR(45) NOT NULL,
    `password` TEXT NOT NULL,
    PRIMARY KEY (`username`));

CREATE TABLE IF NOT EXISTS `spring`.`otp` (
    `username` VARCHAR(45) NOT NULL,
    `code` VARCHAR(45) NOT NULL,
    PRIMARY KEY (`username`));
