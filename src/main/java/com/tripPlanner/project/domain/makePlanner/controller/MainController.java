package com.tripPlanner.project.domain.makePlanner.controller;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tripPlanner.project.domain.makePlanner.dto.FoodDto;
import com.tripPlanner.project.domain.makePlanner.entity.Accom;
import com.tripPlanner.project.domain.makePlanner.entity.Destination;
import com.tripPlanner.project.domain.makePlanner.entity.Food;
import com.tripPlanner.project.domain.makePlanner.entity.Planner;
import com.tripPlanner.project.domain.makePlanner.service.*;
import com.tripPlanner.project.domain.makePlanner.dto.AccomDto;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
@Slf4j
@RequestMapping("/planner")
public class MainController {
    @Autowired
    private AccomService accomService;

    @Autowired
    private FoodService foodService;

    @Autowired
    private DestinationService destinationService;

    @Autowired
    private PlannerService plannerService;

    @Autowired
    private PlannerApiService plannerApiService;

    @Autowired
    private PlaceApiService apiService;

    @ResponseBody
    @PostMapping(value="/getImages", consumes = MediaType.APPLICATION_JSON_VALUE, produces= MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> getImages(@RequestBody Map<String,Object> map) throws JsonProcessingException {
        log.info("POST /planner/getImages...", map);

        // 값을 담을 map객체
        Map<String,Object> datas = new HashMap<>();
        String businessName = (String)map.get("businessName");

        datas.put("image",plannerApiService.getPlaceImage(businessName).block());
        log.info(plannerApiService.getPlaceImage(businessName).block());

        return new ResponseEntity<>(datas, HttpStatus.OK);
    }

    @ResponseBody
    @PostMapping(value="/findDestination", consumes = MediaType.APPLICATION_JSON_VALUE, produces= MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> find_destination(@RequestBody Map<String,Object> map) throws JsonProcessingException {
        log.info("POST /planner/findDestination...");

        // 값을 담을 map객체
        Map<String,Object> datas = new HashMap<>();

        String businessName = (String)map.get("businessName");
        String businessCategory = (String)map.get("businessCategory");
        String streetFullAddress = (String)map.get("streetFullAddress");
        Double xCoordinate = (Double)map.get("coordinate_x");
        Double yCoordinate = (Double)map.get("coordinate_y");
        datas.put("name",businessName);
        datas.put("category",businessCategory);
        datas.put("address",streetFullAddress);
        datas.put("x",xCoordinate);
        datas.put("y",yCoordinate);

        return new ResponseEntity<Map<String,Object>>(datas, HttpStatus.OK);
    }

    @ResponseBody
    @PostMapping(value="/listDestination", consumes = MediaType.APPLICATION_JSON_VALUE, produces= MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> list_destination(@RequestBody Map<String,Object> map) throws JsonProcessingException {
        log.info("POST /planner/listDestination...");

        // 값을 담을 map객체
        Map<String,Object> datas = new HashMap<>();

        double latitude = (Double)map.get("latitude");
        double longitude = (Double)map.get("longitude");
        int zoom_level = (Integer)map.get("zoomlevel");

        // 이동한 좌표 주변의 모든 데이터를 가져온다.
        List<AccomDto> accomList = accomService.listAccom(longitude, latitude,zoom_level);
        List<FoodDto> foodList = foodService.listFood(longitude, latitude, zoom_level);

        // ObjectMapper 객체 생성
        ObjectMapper objectMapper = new ObjectMapper();

        // 자바 객체를 JSON 문자열로 변환
        String accom_json = objectMapper.writeValueAsString(accomList);
        String food_json = objectMapper.writeValueAsString(foodList);

        datas.put("accomList", accom_json);
        datas.put("foodList", food_json);

        return new ResponseEntity(datas, HttpStatus.OK);
    }

    @ResponseBody
    @PostMapping(value="/addPlanner", consumes = MediaType.APPLICATION_JSON_VALUE, produces= MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String,Object>> add_planner(@RequestBody Map<String,Object> map) {
        String title = (String)map.get("title");
        String areaName = (String)map.get("areaName");
        String description = (String)map.get("description");
        boolean isPublic = (Boolean)map.get("isPublic");
        int day = (Integer)map.get("day");
        String userid = (String)map.get("userid");
        ArrayList<Map<String,Object>> destination = (ArrayList<Map<String,Object>>)map.get("destination");

        log.info("POST /planner/addPlanner...");

        Planner planner = plannerService.addPlanner(title,areaName,description,day,isPublic,userid);
        Map<String,Object> datas = destinationService.addDestination(planner, day, destination);

        return new ResponseEntity(datas, HttpStatus.OK);
    }

    @ResponseBody
    @PostMapping(value="/searchDestination", consumes = MediaType.APPLICATION_JSON_VALUE, produces= MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String,Object>> search_destination(@RequestBody Map<String,Object> map) throws ParseException {
        String type = (String)map.get("type");
        String word = (String)map.get("word");
        String areaname = (String)map.get("areaname");

        Map<String,Object> datas = new HashMap<>();
        log.info("POST /planner/searchDestination..."+word);

        if(type.equals("식당")) {
            System.out.println("keyword : " + word + ", areaname : " + areaname);
            List<FoodDto> searchList = foodService.searchFood(word,areaname);
            datas.put("data",searchList);
        } else if(type.equals("숙소")) {
            System.out.println("keyword : " + word + ", areaname : " + areaname);
            List<AccomDto> searchList = accomService.searchAccom(word,areaname);
            datas.put("data",searchList);
        } else if(type.equals("관광지")) {
            int pageNoNum = (Integer)map.get("pageNo");
            String pageNo = Integer.toString(pageNoNum);
            System.out.println("호출");
            String keyword = word;
            String regionCode = (String)map.get("areacode");
            String hashtag = "";
            String arrange = "A";
            String contentTypeId = "12";
            System.out.println("keyword : " + keyword + ", regionCode : " + regionCode + ", pageNo : " + pageNo);

            // regionCode만 있는 경우
            if (keyword.isEmpty() && !regionCode.isEmpty()) {
                System.out.println("지역 코드만 있을 때 반응");

                Mono<String> result = apiService.getAreaBasedList(regionCode, hashtag, pageNo, arrange, contentTypeId);
                JSONParser jsonParser = new JSONParser();
                Object obj = jsonParser.parse(result.block());
                JSONObject jsonObj = (JSONObject) obj;
                datas.put("data",jsonObj);
            }

            if (!keyword.isEmpty() && !regionCode.isEmpty()) {
                System.out.println("다 있음");
                Mono<String> searchKeywordResult = apiService.getSearchKeyword(keyword.trim(), pageNo, arrange, contentTypeId, regionCode);

                JSONParser jsonParser = new JSONParser();
                Object obj = jsonParser.parse(searchKeywordResult.block());
                JSONObject jsonObj = (JSONObject) obj;
                datas.put("data", jsonObj);
            }


//            if (!keyword.isEmpty() && !regionCode.isEmpty()) {
//                System.out.println("다 있음");
//                Mono<String> areaBasedListResult = apiService.getAreaBasedList(regionCode, hashtag, pageNo, arrange, contentTypeId);
//                Mono<String> searchKeywordResult = apiService.getSearchKeyword(keyword.trim(), pageNo, arrange, contentTypeId);
//
//                Mono<String> result = Mono.zip(areaBasedListResult, searchKeywordResult)
//                        .flatMap(tuple -> {
//                            String areaBasedList = tuple.getT1();
//                            String searchKeyword = tuple.getT2();
//                            return apiService.findCommonDataByCat2AndAreaCode(areaBasedList, searchKeyword);
//                        })
//                        .switchIfEmpty(Mono.just("[]"))
//                        .doOnTerminate(() -> System.out.println("findCommonDataByCat2AndAreaCode 호출 종료"));
//
//                JSONParser jsonParser = new JSONParser();
//                Object obj = jsonParser.parse(result.block());
//                JSONObject jsonObj = (JSONObject) obj;
//                System.out.println(jsonObj);
//                datas.put("data", jsonObj);
//            }

        } else {
            System.out.println("error");
            return new ResponseEntity(null, HttpStatus.BAD_REQUEST);
        }
        return new ResponseEntity(datas, HttpStatus.OK);
    }

    @ResponseBody
    @PostMapping(value="/deletePlanner", consumes = MediaType.APPLICATION_JSON_VALUE, produces= MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String,Object>> delete_Planner(@RequestBody Map<String,Object> map) throws ParseException {
        log.info("POST /planner/deletePlanner...");

        Map<String,Object> datas = new HashMap<>();

        int plannerid = Integer.parseInt((String)map.get("plannerid"));
        System.out.println(plannerid);
        String message = plannerService.deletePlanner(plannerid);
        datas.put("message",message);

        return new ResponseEntity(datas, HttpStatus.OK);
    }

    @ResponseBody
    @PostMapping(value="/updatePlanner", consumes = MediaType.APPLICATION_JSON_VALUE, produces= MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String,Object>> update_planner(@RequestBody Map<String,Object> map) {
        if(map.get("plannerid") == null) {
            return new ResponseEntity(null, HttpStatus.BAD_REQUEST);
        }
        int plannerid = (Integer)map.get("plannerid");

        String title = (String)map.get("title");
        String areaName = (String)map.get("areaName");
        String description = (String)map.get("description");
        boolean isPublic = (Boolean)map.get("isPublic");
        int day = (Integer)map.get("day");
        String userid = (String)map.get("userid");
        ArrayList<Map<String,Object>> destination = (ArrayList<Map<String,Object>>)map.get("destination");

        log.info("POST /planner/updatePlanner...", map);

        Planner planner = plannerService.updatePlanner(plannerid,title,areaName,description,day,isPublic,userid);
        Map<String,Object> datas = destinationService.addDestination(planner, day, destination);

        return new ResponseEntity(datas, HttpStatus.OK);
    }

    @ResponseBody
    @PostMapping(value="/bringPlanner", consumes = MediaType.APPLICATION_JSON_VALUE, produces= MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String,Object>> bring_planner(@RequestBody Map<String,Object> map) {
//        if(map.get("plannerid") == null) {
//            return new ResponseEntity(null, HttpStatus.BAD_REQUEST);
//        }
        int plannerid = (Integer)map.get("plannerid");

        log.info("POST /planner/bringPlanner...",plannerid);

        List<Destination> destinations = destinationService.bringPlanner(plannerid);
        Map<String,Object> datas = new HashMap<>();
        datas.put("destinations",destinations);

        return new ResponseEntity(datas, HttpStatus.OK);
    }

}