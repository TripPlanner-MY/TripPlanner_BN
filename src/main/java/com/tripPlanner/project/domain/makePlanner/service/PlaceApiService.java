package com.tripPlanner.project.domain.makePlanner.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.DefaultUriBuilderFactory;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class PlaceApiService {
    private final WebClient webClient;


    @Value("${api.service.key2}")
    private String serviceKey;

    @Value("${google.api.key2}")
    private String googleKey;

    public PlaceApiService(WebClient.Builder webClientBuilder) {
        DefaultUriBuilderFactory factory = new DefaultUriBuilderFactory();
        // 쿼리 파라미터 인코딩을 하지 않도록 설정
        factory.setEncodingMode(DefaultUriBuilderFactory.EncodingMode.NONE);

        // WebClient를 생성할 때 이 factory를 사용
        this.webClient = WebClient.builder()
                .uriBuilderFactory(factory)
                .build();
    }

    // 검색어, 지역, 태그를 모두 입력했을 때 실행할 메서드
    public Mono<String> findCommonDataByCat2AndAreaCode(String areaBasedListResult, String searchKeywordResult) {
        try {
            // JSON 파싱
            ObjectMapper mapper = new ObjectMapper();
            JsonNode areaBasedListNode = mapper.readTree(areaBasedListResult);
            JsonNode searchKeywordNode = mapper.readTree(searchKeywordResult);

            // items 추출
            JsonNode areaBasedListItems = areaBasedListNode.path("items").path("item");
            JsonNode searchKeywordItems = searchKeywordNode.path("items").path("item");

            System.out.println("areaBasedListItems : " + areaBasedListItems);
            System.out.println("searchKeywordItems : " + searchKeywordItems);

            // 공통 데이터를 저장할 리스트
            List<JsonNode> commonItems = new ArrayList<>();


            for (JsonNode areaItem : areaBasedListItems) {
                String areaItemContentId = areaItem.path("contentid").asText();
                String areaItemHashtag = areaItem.path("hashtag").asText();  // hashtag 값 추출
                String areaItemKeyword = areaItem.path("keyword").asText();  // keyword 값 추출

                for (JsonNode searchItem : searchKeywordItems) {
                    String searchItemContentId = searchItem.path("contentid").asText();

                    String searchItemHashtag = searchItem.path("hashtag").asText(); // hashtag 값 추출
                    String searchItemKeyword = searchItem.path("keyword").asText(); // keyword 값 추출

                    // hashtag와 keyword가 모두 일치하는지 확인
                    if (areaItemContentId.equals(searchItemContentId) &&
                            areaItemHashtag.equals(searchItemHashtag) &&
                            areaItemKeyword.equals(searchItemKeyword)) {
                        commonItems.add(areaItem);
                    }
                }
            }


            // 결과 JSON 생성
            ObjectNode resultBody = mapper.createObjectNode();
            ObjectNode itemsNode = mapper.createObjectNode();

            // items 내부에 item 배열 추가
            itemsNode.set("item", mapper.valueToTree(commonItems));

            // items와 totalCount 추가
            resultBody.set("items", itemsNode);
            resultBody.put("totalCount", commonItems.size());

            // JSON 변환 후 반환
            String resultJson = mapper.writeValueAsString(resultBody);
            return Mono.just(resultJson);

        } catch (JsonProcessingException e) {
            // JSON 처리 중 예외 발생 시 Mono.error로 반환
            return Mono.error(new RuntimeException("Error processing JSON", e));
        }
    }


    // 검색어에 맞춰 데이터를 가져오는 함수 (관광지 코스)
    public Mono<String> getSearchKeyword(String keyword, String pageNo, String arrange, String contentTypeId, String areaCode) {
//        System.out.println("service의 getSearchKeyword함수 Keyword : " + keyword);
        // URL을 수동으로 구성
        String url = "https://apis.data.go.kr/B551011/KorService1/searchKeyword1"
                + "?serviceKey=" + serviceKey
                + "&numOfRows=10"
                + "&MobileApp=AppTest"
                + "&MobileOS=ETC"
                + "&areaCode=" + areaCode
                + "&arrange=" + arrange
                + "&contentTypeId=" + contentTypeId
                + "&keyword=" + keyword
                + "&_type=json";

        // pageNo가 null이면 아예 포함하지 않음
        if (pageNo != null) {
            url += "&pageNo=" + pageNo;
        }
        System.out.println("keyword URL : " + url);

        // WebClient를 사용하여 API 호출
        return webClient.get()
                .uri(url)  // 인코딩 없이 URL을 그대로 전달
                .retrieve()
                .bodyToMono(String.class).flatMap(response -> {
                    try {
                        // JSON 응답을 파싱하여 JsonNode로 변환
                        JsonNode responseNode = new ObjectMapper().readTree(response);

                        // body 데이터만 추출하여 반환
                        JsonNode items = responseNode.path("response").path("body");

                        // JsonNode 그대로 반환
                        return Mono.just(items.toString());  // JsonNode를 그대로 JSON 형식의 문자열로 반환

                    } catch (JsonProcessingException e) {
                        return Mono.error(new RuntimeException("Error processing JSON", e));  // JSON 처리 중 오류가 발생하면 에러 반환
                    }
                });
    }

    // 구글 Places API 호출 함수
    public Mono<String> getGooglePlacesData(String keyword) {
        // 구글 Places API 요청 URL 생성
        String googlePlacesUrl = "https://maps.googleapis.com/maps/api/place/textsearch/json"
                + "?query=" + keyword
                + "&key=" + googleKey;

        return webClient.get()
                .uri(googlePlacesUrl)
                .retrieve()
                .bodyToMono(String.class)
                .flatMap(response -> Mono.just(response));  // 구글 Places API 응답 그대로 반환
    }


    // 지역 및 해시태그에 맞춰 데이터를 가져오는 함수
    public Mono<String> getAreaBasedList(String regionCode, String hashtag, String pageNo, String arrange, String contentTypeId) {
        // URL을 수동으로 구성
        String url = "https://apis.data.go.kr/B551011/KorService1/areaBasedList1"
                + "?serviceKey=" + serviceKey
                + "&numOfRows=10"
                + "&MobileApp=AppTest"
                + "&MobileOS=ETC"
                + "&arrange=" + arrange
                + "&areaCode=" + (regionCode != null && !regionCode.isEmpty() ? regionCode : "")
                + "&contentTypeId=" + contentTypeId
                + "&cat2=" + (hashtag != null && !hashtag.isEmpty() && hashtag.length() <= 5 ? hashtag : "")
                + "&cat3=" + (hashtag != null && !hashtag.isEmpty() && hashtag.length() > 5 ? hashtag : "")
                + "&_type=json";
        System.out.println("URL : " + url);
        // pageNo가 null이면 아예 포함하지 않음
        if (pageNo != null) {
            url += "&pageNo=" + pageNo;
        }
//        System.out.println(url);

        // WebClient를 사용하여 API 호출
        return webClient.get()
                .uri(url)  // 인코딩 없이 URL을 그대로 전달
                .retrieve()
                .bodyToMono(String.class)
                .flatMap(response -> {
                    try {
                        // JSON 응답을 파싱하여 JsonNode로 변환
                        JsonNode responseNode = new ObjectMapper().readTree(response);

                        // body 데이터만 추출하여 반환
                        JsonNode items = responseNode.path("response").path("body");

                        // JsonNode 그대로 반환
                        return Mono.just(items.toString());  // JsonNode를 그대로 JSON 형식의 문자열로 반환

                    } catch (JsonProcessingException e) {
                        return Mono.error(new RuntimeException("Error processing JSON", e));  // JSON 처리 중 오류가 발생하면 에러 반환
                    }
                });
    }

}
