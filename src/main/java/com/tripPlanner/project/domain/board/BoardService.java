package com.tripPlanner.project.domain.board;

import com.tripPlanner.project.domain.makePlanner.entity.Destination;
import com.tripPlanner.project.domain.makePlanner.entity.Planner;
import com.tripPlanner.project.domain.makePlanner.repository.DestinationRepository;
import com.tripPlanner.project.domain.makePlanner.repository.PlannerRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class BoardService {

    private final BoardRepository boardRepository;
    private final DestinationRepository destinationRepository;
    private final PlannerRepository plannerRepository;

    // 플래너 전체를 가져와서 게시판에 띄우기
    public Page<BoardDto> getPlannersForBoard(Pageable pageable) {
        // 공개된 플래너를 페이징 처리하여 조회
        return boardRepository.findByIsPublicTrue(pageable)
                .map(planner -> BoardDto.builder()
                        .plannerID(planner.getPlannerID())
                        .plannerTitle(planner.getPlannerTitle())
                        .createAt(planner.getCreateAt())
                        .day(planner.getDay())
                        .username(planner.getUser().getUsername())
                        .thumbnailImage(getThumbnailImage(planner.getPlannerID()))
                        .area((planner.getArea()))
                        .description(planner.getDescription())
                        .userId(planner.getUser().getUserid())
                        .userProfileImg(planner.getUser().getImg())
                        .isPublic(planner.isPublic())
                        .build());

    }

    public String getThumbnailImage(int plannerID) {
        // 플래너 조회
        Planner planner = boardRepository.findById(plannerID)
                .orElseThrow(() -> new IllegalArgumentException("플래너를 찾을 수 없습니다."));

        // 첫 번째 날과 첫 번째 dayOrder에 해당하는 Destination 이미지 조회
        Destination destination = destinationRepository.findFirstDestinationForPlanner(plannerID, 1, 1);

        // 해당 Destination의 이미지 URL 반환
        return destination != null ? destination.getImage() : null;
    }

    //여행 계획 반환하는 메서드
    public int getTotalPlans() {
        return (int) plannerRepository.count();
    }
}
