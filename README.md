## Auth API Server Project

### 1. 개요
- 인증서버 개발 연습
- 최소 기능 설계

### 2. 기능 정의
1. 회원 가입
2. 회원 인증
3. 회원 정보 수정
4. 회원 탈퇴

### 3. 모델링
- 회원 엔티티
  - id, email, name, password

### 4. 기능 정의
- 회원 가입
  - 프로세스 
    1. email, name, password를 통해 가입 요청
    2. 요청을 redis에 임시 저장
    3. 사용자가 인증메일 링크 클릭 시 가입 완료
  - 암호화
    - 요청 시 password는 AES256 암호화
    - Table 저장 시 BCrypt 암호화
    

- 회원 인증
  - 프로세스
    1. email, password를 통해 인증 요청
    2. 인증 후 토큰 발행 (인증 토큰, 리프레시 토큰)
    3. 리프레시 토큰은 member_refresh 테이블에 저장
  - 암호화
    - 요청 시 password는 AES256 암호화
  
- 인증 만료
  - 프로세스
    1. 로그아웃 요청 (header에 토큰 첨부)
    2. 토큰의 subject와 요청 email이 같은지 검증
    3. 같으면 member_refresh 테이블에서 제거
    
작성중

### 5. 테스트
