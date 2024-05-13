
CREATE DATABASE IF NOT EXISTS `pythonlogin` DEFAULT CHARACTER SET utf8 COLLATE UTF8_general_ci;
use `pythonlogin`;

CREATE TABLE IF NOT EXISTS user (
	id int NOT NULL auto_increment,
	name varchar(255) NOT NULL,
    department varchar(255) NOT NULL,
    position varchar(255) NOT NULL,
    salary float NOT NULL,
    manager boolean NOT NULL, 
    contact int NOT NULL,
    PRIMARY KEY (id)
);

Create TABLE IF NOT EXISTS room(
	id int NOT NULL auto_increment,
    Name varchar(255) NOT NULL,
    cost float(5,2) NOT NULL,
	availbility boolean NOT NULL,
    max_occupancy int NOT NULL,
    smoking boolean NOT NULL,
    rating float NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS logs(
	id int NOT NULL auto_increment,
    date datetime NOT NULL,
    user int,
	msg varchar(255),
    PRIMARY KEY (id),
    FOREIGN KEY (user) REFERENCES user(id) 
);
