package com.example.backend.like.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.Hibernate;

import java.io.Serializable;
import java.util.Objects;

@Getter
@Setter
@ToString
@Embeddable
public class BoardLikeId implements Serializable {
    private static final long serialVersionUID = 7449841111793311376L;
    @Column(name = "board_id", nullable = false)
    private Integer boardId;

    @Column(name = "member_id", nullable = false)
    private Long memberId;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || Hibernate.getClass(this) != Hibernate.getClass(o)) return false;
        BoardLikeId entity = (BoardLikeId) o;
        return Objects.equals(this.boardId, entity.boardId) &&
                Objects.equals(this.memberId, entity.memberId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(boardId, memberId);
    }

}