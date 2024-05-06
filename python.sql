
drop table Client, Admin, room, logs;
CREATE DATABASE IF NOT EXISTS `pythonlogin` DEFAULT CHARACTER SET utf8 COLLATE UTF8_general_ci;
use `pythonlogin`;

CREATE TABLE IF NOT EXISTS Client (
	id int NOT NULL auto_increment,
    name varchar(255) NOT NULL,
    password varchar(255) NOT NULL,
    email varchar(100) NOT NULL,
    card int,
    membership bool NOT NULL,
    points int NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS Admin(
	id int NOT NULL auto_increment,
    name VARCHAR(255) NOT NULL,
    password varchar(255) NOT NULL,
    department varchar(255) NOT NULL,
    position varchar(255) NOT NULL,
    salary float(50,2) NOT NULL,
    manager bool NOT NULL,
    contact int NOT NULL, 
    rating Float,
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
    PRIMARY KEY (id)
);
