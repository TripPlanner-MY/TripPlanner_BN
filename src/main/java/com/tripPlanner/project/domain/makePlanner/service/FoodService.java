package com.tripPlanner.project.domain.makePlanner.service;

import com.tripPlanner.project.domain.makePlanner.dto.FoodDto;
import com.tripPlanner.project.domain.makePlanner.entity.Food;
import com.tripPlanner.project.domain.makePlanner.repository.FoodRepository;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.swing.text.html.Option;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
@Slf4j
public class FoodService {

    private double zoomLevel_x[] = {0,0,0,0,0,0,0,0,0,0,0,0,0.004,0.0018};  // 8~13 zoomlevel의 x,y변동 값
    private double zoomLevel_y[] = {0,0,0,0,0,0,0,0,0,0,0,0,0.0025,0.001};  // 8~13 zoomlevel의 x,y변동 값

    @Autowired 
    private FoodRepository foodRepository;

    @Autowired
    private PlannerApiService plannerApiService;

    public List<FoodDto> listFood(double x, double y,int zoom_level) {
        double xStart = x-zoomLevel_x[zoom_level];
        double yStart = y-zoomLevel_y[zoom_level];
        double xEnd = x+zoomLevel_x[zoom_level];
        double yEnd = y+zoomLevel_y[zoom_level];

        List<Food> foods = foodRepository.selectFoodAll(xStart,yStart,xEnd,yEnd);

        List<FoodDto> list = new ArrayList<FoodDto>();

        FoodDto foodDto = new FoodDto();
        foods.forEach(el->{
            list.add(foodDto.entityToDto(el));
        });
        return list;
    }

    @Transactional
    public List<FoodDto> searchFood(String word, String areaname) {
        try {
            List<Food> foods = new ArrayList<>();

            if(areaname.equals("강원도"))
                areaname = "강원";
            if(word.equals("")) {
                log.info("키워드를 입력하지않음");
                foods = foodRepository.searchAreaFood(areaname);
            } else {
                foods = foodRepository.searchFood(word,areaname);
            }
            List<FoodDto> list = new ArrayList<FoodDto>();

            FoodDto foodDto = new FoodDto();
            foods.forEach(el->{
                list.add(foodDto.entityToDto(el));
            });
            return list;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Transactional
    public List<FoodDto> getImage(List<FoodDto> foods) {
        List<FoodDto> getResults = new ArrayList<FoodDto>();
        try {
            foods.forEach(el->{
                el.setImage(plannerApiService.getPlaceImage(el.getName()).block());
                getResults.add(el);
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
        return getResults;
    }
}
