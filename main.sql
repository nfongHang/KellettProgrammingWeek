CREATE TABLE IF NOT EXISTS class (
	class_id	INTEGER NOT NULL,
	class_score	INTEGER,
	PRIMARY KEY(class_id)
);
CREATE TABLE IF NOT EXISTS house (
	house VARCHAR(32) NOT NULL,
	house_score	INTEGER,
	PRIMARY KEY(house)
);
CREATE TABLE IF NOT EXISTS questions (
	question_id	INTEGER NOT NULL,
	question_desc INTEGER,
	PRIMARY KEY(question_id)
);
CREATE TABLE IF NOT EXISTS questions_to_inputs (
	question_id	INTEGER NOT NULL,
	inputset_id	INTEGER NOT NULL,
	inputset_data TEXT,
	inputset_answer VARCHAR(32),
	PRIMARY KEY(question_id,inputset_id)
);
CREATE TABLE IF NOT EXISTS user_solutions (
	uid	INTEGER NOT NULL,
	inputset_id	INTEGER NOT NULL,
	complete	BOOLEAN,
	PRIMARY KEY(uid,inputset_id)
);
CREATE TABLE IF NOT EXISTS users (
	uid	INTEGER NOT NULL,
	house	VARCHAR(32),
	class_id	INTEGER,
	user_email	VARCHAR(255),
	username	VARCHAR(64),
	pwd_hash	VARCHAR(72),
    pwd_salt	VARCHAR(22),
	user_score	INTEGER,
	PRIMARY KEY(uid)
);
COMMIT;