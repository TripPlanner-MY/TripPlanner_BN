package com.tripPlanner.project.domain.tourist;

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
public class ApiService {

    // contentTypeId : 관광타입 (12:관광지, 14:문화시설, 15:축제공연행사, 25:여행코스, 28:레포츠, 32:숙박, 38:쇼핑, 39:음식점) ID


    private final WebClient webClient;


    @Value("${api.service.key}")
    private String serviceKey;

    @Value("${google.api.key}")
    private String googleKey;

    public ApiService(WebClient.Builder webClientBuilder) {
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

//            System.out.println("areaBasedListItems : " + areaBasedListItems);
//            System.out.println("searchKeywordItems : " + searchKeywordItems);

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
    public Mono<String> getSearchKeyword(String keyword, String pageNo, String arrange, String contentTypeId) {
//        System.out.println("service의 getSearchKeyword함수 Keyword : " + keyword);
        // URL을 수동으로 구성
        String url = "https://apis.data.go.kr/B551011/KorService1/searchKeyword1"
                + "?serviceKey=" + serviceKey
                + "&numOfRows=10"
                + "&MobileApp=AppTest"
                + "&MobileOS=ETC"
                + "&arrange=" + arrange
                + "&contentTypeId=" + contentTypeId
                + "&keyword=" + keyword
                + "&_type=json";

        // pageNo가 null이면 아예 포함하지 않음
        if (pageNo != null) {
            url += "&pageNo=" + pageNo;
        }
        System.out.println("keyword url : " + url);

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

    public Mono<String> getSearchKeywordByTourist(String keyword, String pageNo, String arrange) {
        // URL을 수동으로 구성
        String url = "https://apis.data.go.kr/B551011/KorService1/searchKeyword1"
                + "?serviceKey=" + serviceKey
                + "&numOfRows=10"
                + "&MobileApp=AppTest"
                + "&MobileOS=ETC"
                + "&arrange=" + arrange
                + "&contentTypeId="
                + "&keyword=" + keyword
                + "&_type=json";

        // pageNo가 null이면 아예 포함하지 않음
        if (pageNo != null) {
            url += "&pageNo=" + pageNo;
        }

        // ObjectMapper 인스턴스 공유
        ObjectMapper objectMapper = new ObjectMapper();

        return webClient.get()
                .uri(url)
                .retrieve()
                .bodyToMono(String.class)
                .flatMap(response -> {
                    try {
                        // JSON 응답을 파싱하여 JsonNode로 변환
                        JsonNode responseNode = objectMapper.readTree(response);

                        // body 데이터만 추출하여 반환
                        JsonNode items = responseNode.path("response").path("body").path("items");

                        // 만약 'items'가 비어 있다면, 구글 Places API 호출
                        if (items.isEmpty()) {
                            return getGooglePlacesData(keyword)
                                    .flatMap(placesResponse -> {
                                        JsonNode googlePlacesData;
                                        try {
                                            googlePlacesData = objectMapper.readTree(placesResponse);
                                        } catch (JsonProcessingException e) {
                                            return Mono.error(new RuntimeException("Error parsing Google Places API response", e));
                                        }

                                        JsonNode results = googlePlacesData.path("results");

                                        // 구글 Places 데이터에서 첫 번째 항목만 추출
                                        if (!results.isEmpty()) {
                                            JsonNode firstResult = results.get(0); // 첫 번째 결과

                                            // 가공된 데이터를 기존 형식으로 변환
                                            ObjectNode placeNode = objectMapper.createObjectNode();
//                                            placeNode.put("contentid", firstResult.path("place_id").asText());  // place_id를 contentid로 사용
//                                            placeNode.put("title", firstResult.path("name").asText());
//                                            placeNode.put("addr1", firstResult.path("formatted_address").asText());
                                            placeNode.put("mapx", firstResult.path("geometry").path("location").path("lng").asDouble());
                                            placeNode.put("mapy", firstResult.path("geometry").path("location").path("lat").asDouble());

                                            // firstimage 가공
                                            if (firstResult.has("photos") && firstResult.path("photos").isArray()) {
                                                // 첫 번째 사진의 reference를 사용하여 이미지 URL 생성
                                                String photoReference = firstResult.path("photos").get(0).path("photo_reference").asText();
                                                String photoUrl = "https://maps.googleapis.com/maps/api/place/photo?maxwidth=400&photoreference="
                                                        + photoReference + "&key=" + googleKey;
                                                placeNode.put("firstimage", photoUrl);
                                            }

                                            // 결과를 기존 형식으로 담은 ArrayNode 생성
                                            ArrayNode modifiedResults = objectMapper.createArrayNode();
                                            modifiedResults.add(placeNode);

                                            // 가공된 결과를 반환
                                            ObjectNode modifiedResponseNode = objectMapper.createObjectNode();
                                            modifiedResponseNode.set("items", modifiedResults);
                                            return Mono.just(modifiedResponseNode.toString());
                                        } else {
                                            // 결과가 없다면 빈 배열 반환
                                            ObjectNode emptyResponseNode = objectMapper.createObjectNode();
                                            emptyResponseNode.set("items", objectMapper.createArrayNode());
                                            return Mono.just(emptyResponseNode.toString());
                                        }
                                    });
                        } else {
                            // 한국 관광공사 API에서 데이터가 있을 경우 그대로 반환
                            return Mono.just(items.toString());
                        }

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
                + "&numOfRows=20"
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

    // 코스 ID를 바탕으로 상세 데이터를 가져오는 함수
    public Mono<String> getDetailInfo(String courseId, String contentTypeId) {
        // URL을 수동으로 구성
        String url = "https://apis.data.go.kr/B551011/KorService1/detailInfo1"
                + "?serviceKey=" + serviceKey
                + "&pageNo=1"
                + "&numOfRows=20"
                + "&MobileApp=AppTest"
                + "&MobileOS=ETC"
                + "&contentId=" + courseId
                + "&contentTypeId=" + contentTypeId
                + "&_type=json";

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

    // 코스 ID를 바탕으로 상세 데이터를 가져오는 함수 (홈페이지, 상세 설명 등 포함된 정보)
    public Mono<String> getDetailCommon(String courseId) {
        // URL을 수동으로 구성
        String url = "https://apis.data.go.kr/B551011/KorService1/detailCommon1"
                + "?serviceKey=" + serviceKey
                + "&pageNo="
                + "&numOfRows=10"
                + "&MobileApp=AppTest"
                + "&MobileOS=ETC"
                + "&contentId=" + courseId
                + "&defaultYN=Y"
                + "&firstImageYN=Y"
                + "&addrinfoYN=Y"
                + "&mapinfoYN=Y"
                + "&overviewYN=Y"
                + "&_type=json";
        System.out.println("url : " + url);
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

    // 키워드로 구글 API를 요청해 모든 이미지를 받아오는 함수
    public Mono<Map<String, Object>> searchPlacesByKeyword(String keyword) {
        // URL과 파라미터 생성
        String url = "https://maps.googleapis.com/maps/api/place/textsearch/json" + "?query=" + keyword + "&key=" + googleKey;
        System.out.println("keyword : " + keyword);

        // WebClient를 사용하여 Google Places API 호출
        return webClient.get()
                .uri(url)
                .retrieve()
                .bodyToMono(String.class)
                .flatMap(response -> {
                    try {
                        // JSON 응답을 파싱하여 JsonNode로 변환
                        JsonNode responseNode = new ObjectMapper().readTree(response);

                        // "results" 노드를 가져오기
                        JsonNode results = responseNode.path("results");
                        System.out.println("result : " + results);

                        // 모든 장소에서 사진 정보를 추출하여 photoUrls 리스트에 추가
                        List<String> photoUrls = new ArrayList<>();
                        if (results.isArray() && results.size() > 0) {
                            for (JsonNode result : results) {
                                JsonNode photos = result.path("photos");
                                if (photos.isArray() && photos.size() > 0) {
                                    for (JsonNode photo : photos) {
                                        String photoReference = photo.path("photo_reference").asText();
                                        if (!photoReference.isEmpty()) {
                                            // 이미지 URL 생성
                                            String photoUrl = "https://maps.googleapis.com/maps/api/place/photo?maxwidth=1000&photoreference="
                                                    + photoReference + "&key=" + googleKey;
                                            photoUrls.add(photoUrl);
                                        }
                                    }
                                }
                            }

                            // 첫 번째 장소에서 위치 정보 (위도, 경도) 추출
                            JsonNode firstResult = results.get(0); // 첫 번째 결과 가져오기
                            if (firstResult != null && firstResult.has("geometry")) {
                                JsonNode location = firstResult.path("geometry").path("location");
                                double latitude = location.path("lat").asDouble();
                                double longitude = location.path("lng").asDouble();

                                // 결과를 Map으로 반환
                                Map<String, Object> resultMap = new HashMap<>();
                                resultMap.put("photoUrls", photoUrls); // 모든 이미지 URL 리스트
                                resultMap.put("latitude", latitude);
                                resultMap.put("longitude", longitude);

                                return Mono.just(resultMap); // 사진 URL 리스트, 위도, 경도를 포함한 Map 반환
                            } else {
                                return Mono.error(new RuntimeException("No valid location found in first result"));
                            }
                        } else {
                            return Mono.error(new RuntimeException("No results found"));
                        }

                    } catch (Exception e) {
                        return Mono.error(new RuntimeException("Error processing Google Places response", e));
                    }
                });
    }


    // 코스 ID를 바탕으로 상세소개를 가져오는 기능
    public Mono<String> getDetailIntro(String courseId, String contentTypeId) {
        // URL을 수동으로 구성
        String url = "https://apis.data.go.kr/B551011/KorService1/detailIntro1"
                + "?serviceKey=" + serviceKey
                + "&pageNo=" + 1
                + "&numOfRows=10"
                + "&MobileApp=AppTest"
                + "&MobileOS=ETC"
                + "&contentId=" + courseId
                + "&contentTypeId=" + contentTypeId
                + "&_type=json";
        System.out.println("url : " + url);
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
