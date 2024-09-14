-- 기본 사용자 데이터 삽입 (초기 비밀번호는 암호화된 값)
INSERT INTO users (student_id, password, first_login, role)
VALUES 
('20230001', '$2a$10$abc123...', true, 'ROLE_USER'),  -- 학번: 20230001, 초기 비밀번호: 1234
('20230002', '$2a$10$abc123...', true, 'ROLE_USER'),  -- 학번: 20230002, 초기 비밀번호: 1234
('20230003', '$2a$10$abc123...', true, 'ROLE_USER');  -- 학번: 20230003, 초기 비밀번호: 1234
