package com.tripPlanner.project.domain.tourist;

import lombok.Getter;
import lombok.Setter;



@Getter
@Setter
public class ApiRequest {
    // 검색어
    private String keyword;

    // 지역코드
    private String regionCode;

    // 필터 태그
    private String hashtag;

    // 현재 페이지 넘버
    private String pageNo;

    // 정렬 기준 (O=제목순, Q=수정일순, R=생성일순)
    private String arrange;

    // 고유 아이디 (코스정보는 안의 데이터가 10개가 들어있더라도 ContentId는 동일 (SubContentId가 존재함)
    // SubContentId로 ContentTypeId를 지정하지 않고 검색 시 각각의 정보는 받아와짐
    private String contentId;

    // 관광타입(12:관광지, 14:문화시설, 15:축제공연행사, 25:여행코스, 28:레포츠, 32:숙박, 38:쇼핑, 39:음식점) ID
    private String contentTypeId;

    private String mapX;
    private String mapY;



    // regionCode : 지역코드
    //"1": "서울",
    //"2": "인천",
    //"3": "대전",
    //"4": "대구",
    //"5": "광주",
    //"6": "부산",
    //"7": "울산",
    //"8": "세종",
    //"31": "경기",
    //"32": "강원",
    //"33": "충북",
    //"34": "충남",
    //"35": "경북",
    //"36": "경남",
    //"37": "전북",
    //"38": "전남",
    //"39": "제주"
}
