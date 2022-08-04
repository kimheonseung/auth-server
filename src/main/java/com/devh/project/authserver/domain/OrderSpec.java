package com.devh.project.authserver.domain;

import org.apache.commons.lang3.StringUtils;
import org.springframework.data.jpa.domain.Specification;

import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Join;
import javax.persistence.criteria.JoinType;
import javax.persistence.criteria.Predicate;
import javax.persistence.criteria.Root;

public class OrderSpec {
    public static Specification<Order> memberEmailEquals(final String memberEmail) {
        return new Specification<Order>() {
            @Override
            public Predicate toPredicate(Root<Order> root, CriteriaQuery<?> query, CriteriaBuilder criteriaBuilder) {
                if(StringUtils.isEmpty(memberEmail))
                    return null;
                Join<Order, Member> join = root.join("member", JoinType.INNER);
                return criteriaBuilder.equal(join.<String>get("email"), memberEmail);
            }
        };
    }

    public static Specification<Order> memberNameLike(final String memberName) {
        return new Specification<Order>() {
            @Override
            public Predicate toPredicate(Root<Order> root, CriteriaQuery<?> query, CriteriaBuilder criteriaBuilder) {
                if(StringUtils.isEmpty(memberName))
                    return null;
                Join<Order, Member> join = root.join("member", JoinType.INNER);
                return criteriaBuilder.like(join.<String>get("name"), "%"+memberName+"%");
            }
        };
    }

    public static Specification<Order> orderStatusEquals(final OrderStatus orderStatus) {
        return new Specification<Order>() {
            @Override
            public Predicate toPredicate(Root<Order> root, CriteriaQuery<?> query, CriteriaBuilder criteriaBuilder) {
                if(orderStatus == null)
                    return null;
                return criteriaBuilder.equal(root.get("status"), orderStatus);
            }
        };
    }
}
