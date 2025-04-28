![header](https://capsule-render.vercel.app/api?type=rect&color=a2d2ff&height=200&section=header&text=나의&nbsp;여행파트너,&nbsp;여행가자&fontSize=40&fontColor=000814&animation=scaleIn&fontAlignY=50&fontAlign=35)


![개요](https://github.com/user-attachments/assets/0258e317-46b3-4885-a891-70b8bc2ed92f)

---

# 시작하기

## 프로젝트 소개


- **여행가자** 는 여행을 갈 때 계획을 생성할 때, 다른 사람들의 정보를 참고해 나만의 여행계획을 만들 수 있게 하는 국내여행 웹사이트입니다.
- 이용자는 여행계획을 만들 수 있는데, 이 때 식당,특정 명소,숙소 등을 자세하게 기록하여 계획을 만들 수 있습니다.
- 검색을 통해 내가 가보지 않았던 가게나 장소들의 정보들을 확인할 수 있습니다.
- 좋아요 기능을 통해 관심목록을 등록하여, 마이페이지에 관심목록을 만들 수 있습니다.
<br>

## ▶️ 개발 동기 및 주요기능
일에 지치고 사람들에게 치이는 현대인들을 위해 빠르고 간편하게 여행을 계획 할 수 있도록 여행가자를 개발하게 되었습니다.

- ### 본인만의 여행 계획을 만들자 <br>
  여행가자에서는 본인만의 여행 플래너를 계획할 수 있습니다.<br>
  여행할 지역의 식당, 숙소, 관광지를 검색하여 플래너에 담을 수 있습니다.<br>
  N일차 별로 여행 루트를 확인할 수 있고 어느정도 거리가 있는지 확인할 수 있습니다.<br>
- ### 마음에 드는 여행 계획을 가져와 자신만의 계획을 세우자<br>
  다른 사람들의 여행 플래너를 찾아보다 마음에 드는 여행 플래너를 찾았다면 해당 플래너를 가져와 본인만의 플래너로 커스텀할 수 있습니다. <br>
- ### 어디로 가야할지 모르겠다면 관광지를 참고하자<br>
  어느 지역에 무엇을 보러 가야할 지 모르겠다면 카테고리별, 지역별, 키워드별로 관광지를 검색하여 플래너를 계획하는데 참고할 수 있습니다. <br>
- ### 계획을 세우기 어렵다면 여행 코스를 참고하자 <br>
  어떤 식으로 플래너를 계획해야할 지 모르겠다면 지역별, 태그별, 키워드별로 관광 코스를 검색하여 플래너를 계획하는데 참고할 수 있습니다. <br>

<br>
<br>

## 팀원 구성

<div align="center">

| **김병관** | **박대해** | **이영훈** | **진찬민** |
| :------: |  :------: | :------: | :------: |
| [<img src="https://github.com/user-attachments/assets/af0d5eb4-895e-4b20-9454-ca2f1c3a38a5" height=150 width=150> <br/> @KIMGACHE](https://github.com/KIMGACHE) | [<img src="https://github.com/user-attachments/assets/2df8160f-5168-47cc-9e1e-58373618cab3" height=150 width=150> <br/> @Dh_park](https://github.com/GotChun) | [<img src="https://github.com/user-attachments/assets/26d9bafc-1819-42e2-ad1d-179ac08d6f3e" height=150 width=150> <br/> @Maze-o](https://github.com/Maze-o) |[<img src="https://github.com/user-attachments/assets/8fd65434-e420-4960-aa76-8c2427bf7278" height=150 width=150> <br/> @CoMong](https://github.com/wlscksals) |

</div>



## 4. 역할 분담

### 🍊김병관

- **주역할**
    - 플래너 생성,수정,삭제,가져오기 기능 담당
- **보조역할**
    - 플래너 생성페이지 디자인

<br>
    
### 👻박대해

- **주역할**
    - JWT기반 로그인 기능 및 시큐리티 전반 담당
- **보조역할**
    - 메인페이지 디자인 작업보조

<br>

### 😎이영훈

- **주역할**
    - 여행 계획 게시판, 관광지 리스트, 관광지 코스 리스트, 각각의 자세히 보기 페이지 
- **보조역할**
    - 메인, 헤더, 전반적인 디자인

<br>

### 🐬진찬민

- **주역할**
    - 회원가입 기능 및 회원정보 수정, 삭제
- **보조역할**
    - 회원가입 페이지, 마이페이지 디자인
    
<br>

## ▶️ 개발 환경
|-|개발 환경|
|---------------|----------------|
|IDE|IntelliJ Idea , VSCode|
|JDK|JDK 21|
|SpringBoot Version|3.4.0|
|Build Tool|gradle|
|DBMS|MariaDB|
|Connection Pool|HikariCP|
|Version Control|Git|
|Repository Hosting|GitHub|
|Testing Framework|JUnit5|
|Security|Spring Security|
|협업 툴|Notion,Discord|
|디자인|Figma|
<br/>

## ▶️ 사용 API
|용도|제공|API 문서|
|---------------|----------------|------------------------|
|Oauth2 로그인|구글|[링크](https://developers.google.com/identity/protocols/oauth2?hl=ko)|
|Oauth2 로그인|네이버|[링크](https://developers.naver.com/docs/login/api/api.md)|
|Oauth2 로그인|카카오|[링크](https://developers.kakao.com/docs/latest/ko/kakaologin/rest-api)|
|관광지,관광코스|공공데이터포털|[링크](https://www.data.go.kr/tcs/dss/selectApiDataDetailView.do?publicDataPk=15101578)|
|구글Place|구글|[링크](https://developers.google.com/maps/documentation/places/web-service/search?hl=ko)|

<br/>

## ▶️ SKILLS
#### BACKEND
![JAVA](https://img.shields.io/badge/Java-007396?style=for-the-badge&logo=Java&logoColor=white)
![SpringBoot](https://img.shields.io/badge/springboot-6DB33F?style=for-the-badge&logo=springboot&logoColor=white)
![SpringSecurity](https://img.shields.io/badge/springsecurity-6DB33F?style=for-the-badge&logo=springsecurity&logoColor=white)
---

#### FE
![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=HTML5&logoColor=white)
![CSS3](https://img.shields.io/badge/css3-%231572B6.svg?style=for-the-badge&logo=css&logoColor=white)
![JavaScript](https://img.shields.io/badge/javascript-%23323330.svg?style=for-the-badge&logo=javascript&logoColor=%23F7DF1E)
![Axios](https://img.shields.io/badge/Axios-5A29E4?style=for-the-badge&logo=Axios&logoColor=white)
---

#### DATABASE
![Mariadb](https://img.shields.io/badge/Mariadb-4479A1?style=for-the-badge&logo=Mariadb&logoColor=white)
---

#### DEVOPS
![redhat](https://img.shields.io/badge/redhat-EE0000?style=for-the-badge&logo=redhat&logoColor=white)
![Git](https://img.shields.io/badge/Git-F05032?style=for-the-badge&logo=git&logoColor=white)
![Github](https://img.shields.io/badge/Github-181717?style=for-the-badge&logo=Github&logoColor=white)
![intelli-j](https://img.shields.io/badge/intellijidea-000000?style=for-the-badge&logo=intellijidea&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-EC2-FF9900?style=for-the-badge&logo=amazonec2&logoColor=white)
![jenkins](https://img.shields.io/badge/jenkins-D24939?style=for-the-badge&logo=jenkins&logoColor=white)
<br/>


📃: File Tree
---

```
📦src
 ┣ 📂main
 ┃ ┣ 📂generated
 ┃ ┣ 📂java
 ┃ ┃ ┗ 📂com
 ┃ ┃ ┃ ┗ 📂tripPlanner
 ┃ ┃ ┃ ┃ ┗ 📂project
 ┃ ┃ ┃ ┃ ┃ ┣ 📂commons    - 공통적으로 사용하는 파일들
 ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📂config
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜PasswordConfig.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┗ 📜RedisConfig.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📂entity
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜Destination.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜DestinationID.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┗ 📜Planner.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜CookieController.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜HomeController.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┗ 📜SecurityConfig.java
 ┃ ┃ ┃ ┃ ┃ ┣ 📂domain    - 각 역할에 따라 폴더를 나눠서 파일을 생성
 ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📂board    
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜BoardController.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜BoardDto.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜BoardRepository.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┗ 📜BoardService.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📂destination
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜DestinationController.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜Like.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜LikeRepository.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜LikeRequest.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜LikeService.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┗ 📜LikeStatusResponse.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📂login    - 로그인 기능이 있는 파일
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📂auth
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📂handler
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜CustomLogoutHandler.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┗ 📜Oauth2LoginSuccessHandler.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📂jwt
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜JwtAuthenticationFilter.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┗ 📜JwtTokenProvider.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┗ 📜PrincipalDetail.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📂controller
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┗ 📜LoginController.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📂dto
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜JwtToken.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜LoginRequest.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┗ 📜LoginResponse.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📂entity
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜TokenEntity.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┗ 📜TokenRepository.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📂service
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜AuthService.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜CustomOAuth2UserService.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜LoginService.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┗ 📜PrincipalDetailService.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┗ 📜GlobalExceptionHandler.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📂makePlanner    - 여행 계획을 생성하는 부분
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📂controller
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┗ 📜MainController.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📂dto
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜AccomDto.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜DestinationDto.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜FoodDto.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜MapDataDto.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜MapDto.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┗ 📜PlannerDto.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📂entity
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜Accom.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜Destination.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜DestinationID.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜Food.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┗ 📜Planner.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📂repository
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜AccomRepository.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜DestinationRepository.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜FoodRepository.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┗ 📜PlannerRepository.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┗ 📂service
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜AccomService.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜DestinationService.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜FoodService.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜PlaceApiService.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜PlannerApiService.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┗ 📜PlannerService.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📂Mypage    - 마이페이지
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📂config
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┗ 📜WebConfig.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📂controller
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┗ 📜MypageController.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📂entity
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┗ 📜UpdateUserRequest.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┗ 📂Service
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┗ 📜MypageService.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📂signin
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📂controller
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┗ 📜UserController.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📂dto
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┗ 📜UserDto.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📂entity
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┗ 📜UserEntity.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📂repository
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜PlannerRepository.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┗ 📜UserRepository.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📂service
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┗ 📜UserService.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┗ 📜UploadProperties.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┗ 📂tourist
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜ApiController.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜ApiRequest.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┣ 📜ApiService.java
 ┃ ┃ ┃ ┃ ┃ ┃ ┃ ┗ 📜WebClientConfig.java
 ┃ ┃ ┃ ┃ ┃ ┗ 📜ProjectApplication.java
 ┃ ┗ 📂resources
 ┃ ┃ ┣ 📂static
 ┃ ┃ ┃ ┗ 📜index.html
 ┃ ┃ ┗ 📜application.properties 
 
 📦src
 ┣ 📂auth
 ┃ ┗ 📜PrivateRoute.jsx
 ┣ 📂board
 ┃ ┣ 📜Board.jsx
 ┃ ┣ 📜Board.scss
 ┃ ┣ 📜BoardInfo.jsx
 ┃ ┣ 📜Destination.jsx
 ┃ ┣ 📜Destination.scss
 ┃ ┣ 📜DestinationDetails.jsx
 ┃ ┗ 📜DestinationDetails.scss
 ┣ 📂components
 ┃ ┣ 📜Body.jsx
 ┃ ┣ 📜Header.jsx
 ┃ ┣ 📜Header.scss
 ┃ ┣ 📜Main.jsx
 ┃ ┗ 📜Main.scss
 ┣ 📂images
 ┃ ┣ 📜favIcon.png
 ┃ ┣ 📜findway.png
 ┃ ┣ 📜footPrint.png
 ┃ ┣ 📜homepageIcon.png
 ┃ ┣ 📜likeIcon.png
 ┃ ┣ 📜logo.png
 ┃ ┣ 📜logoImage.png
 ┃ ┣ 📜logotitle.png
 ┃ ┣ 📜main.jpg
 ┃ ┣ 📜noImage.png
 ┃ ┣ 📜trip1.png
 ┃ ┗ 📜trip2.png
 ┣ 📂join
 ┃ ┣ 📜Join.jsx
 ┃ ┗ 📜Join.scss
 ┣ 📂login
 ┃ ┣ 📂components
 ┃ ┃ ┣ 📜EmailAuthPage.jsx
 ┃ ┃ ┣ 📜FindIdPage.jsx
 ┃ ┃ ┣ 📜PasswordResetPage.jsx
 ┃ ┃ ┣ 📜UseridInputPage.jsx
 ┃ ┃ ┗ 📜VerifyCodePage.jsx
 ┃ ┣ 📂scss
 ┃ ┃ ┣ 📜EmailAuthPage.scss
 ┃ ┃ ┣ 📜FindIdPage.scss
 ┃ ┃ ┣ 📜ForgotPage.scss
 ┃ ┃ ┣ 📜LoginForm.scss
 ┃ ┃ ┣ 📜PasswordResetPage.scss
 ┃ ┃ ┣ 📜UseridInputPage.scss
 ┃ ┃ ┗ 📜VerifyCodePage.scss
 ┃ ┣ 📜ForgotPage.jsx
 ┃ ┣ 📜LoginForm.jsx
 ┃ ┣ 📜Logout.jsx
 ┃ ┗ 📜SocialLoginHandler.jsx
 ┣ 📂mypage
 ┃ ┣ 📜Mypage.jsx
 ┃ ┣ 📜Mypage.scss
 ┃ ┣ 📜useLikePlanner.js
 ┃ ┣ 📜useMyPage.js
 ┃ ┣ 📜useMyPlanner.js
 ┃ ┗ 📜useProfileImage.js
 ┣ 📂planner
 ┃ ┣ 📂makePlanner
 ┃ ┃ ┣ 📜MakePlanner.jsx
 ┃ ┃ ┗ 📜MakePlanner.scss
 ┃ ┣ 📂Map
 ┃ ┃ ┗ 📜Map.jsx
 ┃ ┣ 📂PlannerDate
 ┃ ┃ ┣ 📜PlannerDate.jsx
 ┃ ┃ ┗ 📜PlannerDate.scss
 ┃ ┗ 📂SideBar
 ┃ ┃ ┣ 📜SideBar.jsx
 ┃ ┃ ┗ 📜SideBar.scss
 ┣ 📂public
 ┃ ┣ 📜public.css
 ┃ ┗ 📜reset.css
 ┣ 📂tourist
 ┃ ┣ 📂jsonFile
 ┃ ┃ ┗ 📜tourist.json
 ┃ ┣ 📜Tourist.jsx
 ┃ ┣ 📜Tourist.scss
 ┃ ┣ 📜TouristInfo.jsx
 ┃ ┣ 📜TouristInfo.scss
 ┃ ┣ 📜TravelCourse.jsx
 ┃ ┣ 📜TravelCourse.scss
 ┃ ┣ 📜TravelCourseInfo.jsx
 ┃ ┗ 📜TravelCourseInfo.scss
 ┣ 📜App.css
 ┣ 📜App.js
 ┣ 📜index.js
 ┗ 📜Mypage.jsx
```
[프로젝트 경로(TREE)]
#
---
#
## ▶️ 주요 END POINT DOC

| URI                           | REQUEST METHOD | DESCRIPTION        |
|-------------------------------|----------------|--------------------|
| /user/mypage/userupdate       | PUT            | 회원정보수정       |
| /user/mypage/upload           | POST           | 이미지업로드       |
| /user/mypage                  | GET            | 사용자 마이페이지  |
| /user/mypage/my-planners      | GET            | 내 플래너 조회     |
| /user/login                   | POST           | 로그인             |
| /user/logout                  | POST           | 로그아웃           |
| /user/findId                  | POST           | 아이디 찾기        |
| /user/reset-password          | POST           | 비밀번호 찾기      |
| /user/join                    | POST           | 회원가입           |
| /user/send-auth-code          | POST           | 인증메일 발송      |
| /tourist-info                 | GET            | 관광지 정보 조회   |
| /travelcourse-info            | GET            | 여행코스 정보 조회 |
| /planner/board                | GET            | 여행계획 조회      |
| /planner/addPlanner           | POST           | 여행계획 생성      |
| /planner/deletePlanner        | GET            | 여행계획 삭제      |
| /planner/updatePlanner        | GET            | 여행계획 수정      |


---
# 주요 의존성 목록
- 	implementation 'org.springframework.boot:spring-boot-starter-data-jpa'   # JPA
- 	implementation 'org.springframework.boot:spring-boot-starter-data-redis'   # 레디스
- 	implementation 'org.springframework.boot:spring-boot-starter-oauth2-client'    # 소셜로그인
- 	compileOnly 'org.projectlombok:lombok'  #lombok
- 	runtimeOnly 'org.mariadb.jdbc:mariadb-java-client' # MariaDB
- 	testImplementation 'org.mockito:mockito-core'  # Mockito
- 	implementation 'org.springframework.boot:spring-boot-starter-webflux'   
- 	implementation group: 'org.springframework.boot', name: 'spring-boot-starter-mail', version: '3.0.5'# JavaMailSender
-	implementation 'io.jsonwebtoken:jjwt-api:0.11.5'  #  JWT
-	implementation group: 'org.springdoc', name: 'springdoc-openapi-starter-webmvc-ui', version: '2.8.1'    # SWAGGER


## ▶️ ERD
![erd](https://github.com/user-attachments/assets/6c0391f9-3d98-4623-8a1d-fb510746a925)
---

## ▶️ 유스케이스 다이어그램
![uml](https://github.com/user-attachments/assets/8e984fba-1fe3-4c18-9c55-b15d1c36361f)
<br/>
---



## 10. 프로젝트 후기

- 김병관 <br>
  웹 개발 프로젝트가 처음이다보니 초반 설계 과정에서의 아쉬움이 크게 남았습니다. 초반의 설계가 엉성했던터라 병합시에 너무 많은시간을 소요했고, 프로젝트의 기능에 대해 확실하게 정하고 갔어야했는데 그러지 못하고 계속 덧붙이다보니 이전의 코드와 이후의 코드가 충돌하는 일도 잦았습니다. 이번 프로젝트를 통해 뭐든 기반이 가장 중요하다고 느꼈고 팀원들과의 의사소통을 좀 더 많이했더라면 하는 아쉬움이 남았습니다. 앞으로는 프로젝트 경험을 쌓아 설계과정에서 모두의 역할을 자세하게 분담하고 팀원들간의 의사소통에 좀 더 신경쓸 수 있도록 노력하겠습니다.
  
- 이영훈 <br>
  초반에 설계 과정에서 제대로 설계를 하지 않고 진행을 다 보니 기능의 추가와 삭제로 인한 프로젝트 마감일 까지의 기능 구현, 불필요한 코드 작성과 삭제가 매우 많아졌다는 것을 깨닳았습니다.백엔드 작업기간을 명확하게 두고 프론트 작업을 해야 프로젝트의 완성도가 매우 높아보인다는것 또한 깨닳았습니다.
  팀원과의 작업물들을 병합할 때 아직 git의 사용법을 미숙한 상태로 진행하다보니 병합간의 충돌, 쓸데없는 브랜치가 많아짐 등의 문제를 겪다 보니 팀 단위의 프로젝트에서는 엄격한 브랜치 관리,병합이 필요하다는 것을 깨닳았습니다. 

- 박대해<br>
초반에 프로젝트를 설계할 때 좀더 디테일하게 설계를 해야하는 필요성을 느꼈습니다. 대략적인 흐름은 정해두고 진행을 하긴 했지만 자세한 내부 로직구성과 같은 부분에 대해서는 정해둔 것 없이 코드작성을 했습니다. 그러고 후에 테스트를 진행해보니 어딘가 맞지 않는 부분이 생겨서 코드 전체적으로 다시 수정하는 일이 생겨 오히려 시간이 더 지체되게 되었습니다. 추후에는 좀 더 자세한 설계를 통해 앞으로 일어날 문제발생을 예방하고 더 원활한 프로젝트 진행을 할 수 있도록 하고싶습니다. 그리고 아무리 내부적으로 잘 짜여진 코드라도 괜찮은 프론트엔드 디자인 없이는 소용없다는 것을 알았습니다. 눈에 보이는 디자인이 별로라면 괜히 그 시스템까지도 그다지 좋아보이지 않는 느낌을 받았습니다.

- 진찬민 <br>

  
<hr>
