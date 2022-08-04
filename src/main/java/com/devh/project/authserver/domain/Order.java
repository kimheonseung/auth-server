package com.devh.project.authserver.domain;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.persistence.*;

import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
@Table(name = "ORDERS")
public class Order {
	
    @Id @GeneratedValue
    @Column(name = "ORDER_ID")
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "MEMBER_ID")
    private Member member;

    @OneToMany(mappedBy = "order", cascade = CascadeType.ALL)
    private List<OrderItem> orderItems = new ArrayList<>();
    
    @OneToOne(cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @JoinColumn(name = "DELIVERY_ID")
    private Delivery delivery;
    
    private Date orderDate;
    
    @Enumerated(EnumType.STRING)
    private OrderStatus status;
    
    // 연관관계
    public void setMember(Member member) {
    	this.member = member;
    	member.getOrders().add(this);
    }
    
    public void addOrderItem(OrderItem orderItem) {
    	orderItems.add(orderItem);
    	orderItem.setOrder(this);;
    }
    
    public void setDelivery(Delivery delivery) {
    	this.delivery = delivery;
    	delivery.setOrder(this);
    }
}
