package com.apifuzzer.generation;

import com.apifuzzer.model.RequestSpec;
import java.util.List;

public interface MutationStrategy {
    List<RequestSpec> mutate(RequestSpec original, int count);
    String getName();
    String getDescription();
}