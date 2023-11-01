/**
  This is the SQL script that will be used to initialize the database schema.
  We will evaluate you based on how well you design your database.
  1. How you design the tables.
  2. How you choose the data types and keys.
  3. How you name the fields.
  In this assignment we will use PostgreSQL as the database.
  */

/** This is test table. Remove this table and replace with your own tables. */
CREATE TABLE user_data (
	id serial PRIMARY KEY,
	phone_number VARCHAR ( 50 ) UNIQUE NOT NULL,
  fullname VARCHAR ( 50 ) NOT NULL,
  password VARCHAR (255 ) NOT NULL,
  login_counter INTEGER DEFAULT 0
);
