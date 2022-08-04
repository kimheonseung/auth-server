package com.devh.project.authserver.domain;

import lombok.Getter;
import lombok.Setter;
import org.springframework.data.jpa.domain.Specification;
import static org.springframework.data.jpa.domain.Specification.where;
import static com.devh.project.authserver.domain.OrderSpec.memberNameLike;
import static com.devh.project.authserver.domain.OrderSpec.orderStatusEquals;

@Getter
@Setter
public class OrderSearch {
    private String memberName;
    private OrderStatus orderStatus;

    public Specification<Order> toSpecification() {
        return where(
                memberNameLike(memberName)
                        .and(orderStatusEquals(orderStatus))
        );
    }
}
