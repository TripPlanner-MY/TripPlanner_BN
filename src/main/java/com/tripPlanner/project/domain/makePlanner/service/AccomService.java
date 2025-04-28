package com.tripPlanner.project.domain.makePlanner.service;


import com.tripPlanner.project.domain.makePlanner.dto.AccomDto;
import com.tripPlanner.project.domain.makePlanner.dto.FoodDto;
import com.tripPlanner.project.domain.makePlanner.entity.Accom;
import com.tripPlanner.project.domain.makePlanner.entity.Food;
import com.tripPlanner.project.domain.makePlanner.repository.AccomRepository;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
@Slf4j
public class AccomService {

    private double zoomLevel_x[] = {0,0,0,0,0,0,0,0,0,0,0,0,0.004,0.0018};  // 8~13 zoomlevel의 x,y변동 값
    private double zoomLevel_y[] = {0,0,0,0,0,0,0,0,0,0,0,0,0.0025,0.001};  // 8~13 zoomlevel의 x,y변동 값

    @Autowired 
    private AccomRepository accomRepository;

    @Autowired
    private PlannerApiService plannerApiService;

    public List<AccomDto> listAccom(double x, double y, int zoom_level) {
        double xStart = x-zoomLevel_x[zoom_level];
        double yStart = y-zoomLevel_y[zoom_level];
        double xEnd = x+zoomLevel_x[zoom_level];
        double yEnd = y+zoomLevel_y[zoom_level];
        List<Accom> accoms = accomRepository.selectMiddle(xStart,yStart,xEnd,yEnd);
        List<AccomDto> list = new ArrayList<AccomDto>();

        accoms.forEach(el->{
            list.add(AccomDto.entityToDto(el));
        });
        return list;
    }

    @Transactional
    public List<AccomDto> searchAccom(String word, String areaname) {
        try {
            List<Accom> accoms = new ArrayList<>();

            if(areaname.equals("강원도"))
                areaname = "강원";
            if(word.equals("")) {
                log.info("키워드를 입력하지않음");
                accoms = accomRepository.searchAreaAccom(areaname);
            } else {
                accoms = accomRepository.searchAccom(word,areaname);
            }
            List<AccomDto> list = new ArrayList<AccomDto>();

            AccomDto accomDto = new AccomDto();
            accoms.forEach(el->{
                list.add(accomDto.entityToDto(el));
            });
            return list;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Transactional
    public List<AccomDto> getImage(List<AccomDto> accoms) {
        List<AccomDto> getResults = new ArrayList<AccomDto>();
        try {
            accoms.forEach(el->{
                el.setImage(plannerApiService.getPlaceImage(el.getName()).block());
                getResults.add(el);
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
        return getResults;
    }
}
