package com.tripPlanner.project.domain.destination;

import com.tripPlanner.project.domain.login.auth.PrincipalDetail;
import com.tripPlanner.project.domain.makePlanner.dto.DestinationDto;
import com.tripPlanner.project.domain.makePlanner.entity.Destination;
import com.tripPlanner.project.domain.makePlanner.entity.Planner;
import com.tripPlanner.project.domain.makePlanner.repository.DestinationRepository;
import com.tripPlanner.project.domain.makePlanner.service.DestinationService;
import com.tripPlanner.project.domain.signin.entity.UserEntity;
import com.tripPlanner.project.domain.tourist.ApiRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
public class DestinationController {

    private final DestinationRepository destinationRepository;
    private final DestinationService destinationService;
    private final LikeService likeService;

    // 플래너 ID에 해당하는 destination 리스트 반환
    @GetMapping("/planner/board/destination")
    public List<DestinationDto> getDestinationsByPlannerId(@RequestParam("plannerID") int plannerID) {
        List<Destination> destinations = destinationRepository.findByPlanner_PlannerID(plannerID);

        // Destination 엔티티를 DTO로 변환하여 반환
        return destinations.stream()
                .map(Destination::toDto) // Destination을 DestinationDto로 변환
                .collect(Collectors.toList());
    }

    // 좋아요 상태 및 카운트 조회
    @GetMapping("/planner/board/likeStatus")
    public ResponseEntity<LikeStatusResponse> getLikeStatus(
            @RequestParam(name = "plannerID") Planner plannerID,
            @AuthenticationPrincipal PrincipalDetail userDetails
    ) {
        System.out.println("ㅎㅇ");
        System.out.println("plannerID : " + plannerID);
        // UserEntity로 변경
        UserEntity userId = userDetails.getUserEntity();
        System.out.println("userID : " + userId);

        LikeStatusResponse response = likeService.getLikeStatus(plannerID, userId);
        return ResponseEntity.ok(response);
    }

    // 좋아요 토글
    @PostMapping("/planner/board/toggleLike")
    public ResponseEntity<LikeStatusResponse> toggleLike(
            @RequestBody LikeRequest likeRequest,
            @AuthenticationPrincipal PrincipalDetail userDetails
    ) {
        UserEntity userId = userDetails.getUserEntity();
        System.out.println("userID : " + userId);
        LikeStatusResponse response = likeService.toggleLike(likeRequest.getPlannerID(), userId);
        return ResponseEntity.ok(response);
    }

    // destination 리스트 클릭 시 tourist페이지로 가서 정보를 띄워주게 할 contentId를 얻어오기
    @PostMapping("/destination-to-tourist")
    public Mono<String> destinaionToTourist(@RequestBody ApiRequest apiRequest) {
        return destinationService.getLocationBasedList(apiRequest.getMapX(), apiRequest.getMapY());
    }

}
