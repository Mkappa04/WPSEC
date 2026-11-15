-- Un database separato per ogni sito del laboratorio.
CREATE DATABASE IF NOT EXISTS wp_vuln;
CREATE DATABASE IF NOT EXISTS wp_hard;
CREATE DATABASE IF NOT EXISTS wp_mixed;
GRANT ALL PRIVILEGES ON wp_vuln.*  TO 'lab'@'%';
GRANT ALL PRIVILEGES ON wp_hard.*  TO 'lab'@'%';
GRANT ALL PRIVILEGES ON wp_mixed.* TO 'lab'@'%';
FLUSH PRIVILEGES;
