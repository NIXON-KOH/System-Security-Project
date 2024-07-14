
CREATE TABLE IF NOT EXISTS room(
	id int not null auto_increment,
    name varchar(255) not null, 
    availability boolean not null,
    max_occupany integer not null,
    smoking boolean not null,
    imgpth varchar(255) not null,
	primary key(id)
);
CREATE TABLE IF NOT EXISTS logs(
	id int not null auto_increment,
    date date not null,
    user int not null,
    msg varchar(255) not null,
	primary key(id),
    foreign key (user) references room(id)
    );

CREATE TABLE IF NOT EXISTS USER(
	id int auto_increment NOT NULL,
	name varchar(255) NOT NULL,
	password varchar(255) NOT NULL,
	email varchar(255) NOT NULL,
	power int NOT NULL,
	IMGPATH varchar(255) NOT NULL,
	TOTPSECRET varchar(255) NOT NULL,
    PRIMARY KEY(id)
    );