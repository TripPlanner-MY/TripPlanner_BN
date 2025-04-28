package com.tripPlanner.project.domain.makePlanner.entity;

import jakarta.persistence.Embeddable;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.io.Serializable;

// 여행 일정에서 특정 날짜에 특정 장소를 식별하는 데 사용하는 클래스
@Embeddable  // 이 클래스는 JPA에서 복합 기본 키를 만들 때 사용
@Data
@NoArgsConstructor
@AllArgsConstructor
public class DestinationID implements Serializable {

    private int plannerID;  // 여행 계획의 고유 ID
    private int day;         // 여행 일정의 특정 날짜 (예: 첫째 날, 둘째 날 등)
    private int dayOrder;    // 해당 날짜 내에서 방문할 장소의 순서 (예: 첫 번째 장소, 두 번째 장소 등)

    // Override 메서드 : 컬렉션에 객체를 추가하거나 비교할 때 호출

    // equals 메서드: 두 DestinationId 객체가 동일한지를 비교
    // 만약 1번 플래너의 1번째날 1번째 장소가 입력돼 있을 때 또 1번 플래너의 1번째날 1번째 장소를 입력하려고 하면 실행할 비교 함수
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;  // 자신과 비교하는 경우 동일함
        if (o == null || getClass() != o.getClass()) return false;  // 비교 대상이 없거나 클래스가 다르면 false 반환

        DestinationID that = (DestinationID) o;

        // plannerID, day, dayOrder가 모두 동일해야 동일한 객체로 간주
        if (plannerID != that.plannerID) return false;
        if (day != that.day) return false;
        return dayOrder == that.dayOrder;
    }

    // hashCode 메서드: 동일한 DestinationId 객체들은 동일한 해시코드를 반환해야 하므로
    // equals 메서드의 동작에 맞춰서 hashCode를 재정의합니다.
    @Override
    public int hashCode() {
        int result = plannerID;
        result = 31 * result + day;  // day와 dayOrder도 해시코드 계산에 포함
        result = 31 * result + dayOrder;
        return result;
    }
}