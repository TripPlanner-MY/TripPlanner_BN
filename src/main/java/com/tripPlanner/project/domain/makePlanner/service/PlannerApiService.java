package com.tripPlanner.project.domain.makePlanner.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

@Service
@Slf4j
public class PlannerApiService {
    @Value("${google.api.key2}")
    private String apiKey;

    private final WebClient.Builder webClientBuilder;

    public PlannerApiService(WebClient.Builder webClientBuilder) {
        this.webClientBuilder = webClientBuilder;
    }

    public Mono<String> getPlaceImage(String keyword) {
        String placeUrl ="https://maps.googleapis.com/maps/api/place/textsearch/json" + "?query=" + keyword + "&key=" +apiKey;

        return webClientBuilder.build()
                .get()
                .uri(placeUrl)
                .retrieve()
                .bodyToMono(Map.class)
                .flatMap(body -> {
                    List<Map<String, Object>> results = (List<Map<String, Object>>) body.get("results");

                    if (results != null && !results.isEmpty()) {
//                        System.out.println("result : "+ results);
                        Map<String, Object> place = results.get(0);
                        List<Map<String, Object>> photos = (List<Map<String, Object>>) place.get("photos");

                        if (photos != null && !photos.isEmpty()) {
                            String photoReference = (String) photos.get(0).get("photo_reference");
                            return Mono.just(getPlacePhoto(photoReference));
                        }
                    }
                    return Mono.just("No image found");
                });
    }

    private String getPlacePhoto(String photoReference) {
        return String.format(
                "https://maps.googleapis.com/maps/api/place/photo?maxwidth=400&photoreference=%s&key=%s",
                photoReference, apiKey
        );
    }
}

