import React, { useEffect, useState } from "react";
import axios from "axios";
import { Card, Col, Row, Spinner, Badge, Container } from "react-bootstrap";
import { useNavigate } from "react-router-dom";
import { LikeContainer } from "../like/LikeContainer.jsx";
import { ReviewLikeContainer } from "../like/ReviewLikeContainer.jsx";
import { useParams } from "react-router";
import { FiMapPin, FiCalendar, FiStar } from "react-icons/fi";

export function MyReview() {
  const [reviews, setReviews] = useState(null);
  const navigate = useNavigate();

  const { memberId } = useParams();

  useEffect(() => {
    axios
      .get(`/api/review/myReview/${memberId}`)
      .then((res) => {
        setReviews(res.data);
      })
      .catch((err) => {
        console.error("리뷰 불러오기 실패", err);
        setReviews([]);
      });
  }, [memberId]);

  const isImageFile = (url) =>
    /\.(jpg|jpeg|png|gif|webp)$/i.test(url?.split("?")[0]);
  const defaultProfileImage = "/user.png";

  if (!reviews) {
    return (
      <Container className="my-5 text-center">
        <div className="spinner-border" role="status" />
      </Container>
    );
  }

  if (reviews.length === 0) {
    return (
      <Container className="my-4 p-4 bg-light rounded shadow">
        <h2 className="text-center mb-4 fw-bold">
          📝 내가 작성한 리뷰
          <span className="ms-2 fs-6 text-muted">(0개)</span>
        </h2>
        <div className="text-center py-5">
          <div className="mb-3">
            <FiStar size={48} className="text-muted" />
          </div>
          <h4 className="text-muted mb-2">아직 작성한 리뷰가 없습니다</h4>
          <p className="text-muted">방문한 시설에 대한 리뷰를 남겨보세요!</p>
        </div>
      </Container>
    );
  }

  // 첫번째 리뷰에서 닉네임 가져와서 제목으로 사용할 때
  const userNickName = reviews[0].memberEmailNickName;

  return (
    <Container className="my-4 p-4 bg-light rounded shadow">
      <h2 className="text-center mb-4 fw-bold">
        📝 {userNickName}님이 쓴 리뷰
        <span className="ms-2 fs-6 text-muted">({reviews.length}개)</span>
      </h2>

      <Row className="g-3">
        {reviews.map((r) => {
          const imageFiles = r.files?.filter(isImageFile) || [];
          const facilityInfo = r.petFacility;
          const hasImages = imageFiles.length > 0;

          return (
            <Col key={r.id} xs={12} sm={6} md={4} lg={3}>
              <Card
                className="h-100 border shadow-sm position-relative"
                onClick={() =>
                  navigate(`/facility/${facilityInfo.id}?focusReviewId=${r.id}`)
                }
                style={{ cursor: "pointer" }}
              >
                <Card.Body className="d-flex flex-column">
                  {/* 시설명 */}
                  <div className="fw-semibold text-truncate text-secondary mb-1">
                    📍 {facilityInfo?.name || "정보 없음"}
                  </div>

                  {/* 별점 */}
                  <div
                    className="mb-2"
                    style={{ color: "#f0ad4e", fontSize: "1.1rem" }}
                  >
                    {"★".repeat(r.rating)}
                  </div>

                  {/* 사진 */}
                  {hasImages && (
                    <>
                      {imageFiles.length === 1 && (
                        <Card.Img
                          variant="top"
                          src={imageFiles[0]}
                          style={{
                            objectFit: "cover",
                            height: "150px",
                            borderRadius: "6px",
                            marginBottom: "8px",
                          }}
                        />
                      )}

                      {(imageFiles.length === 2 ||
                        imageFiles.length === 3 ||
                        imageFiles.length >= 4) && (
                        <div
                          style={{
                            display: "grid",
                            gridTemplateColumns: "1fr 1fr",
                            gridTemplateRows: "1fr 1fr",
                            gap: "4px",
                            height: "150px",
                            borderRadius: "6px",
                            overflow: "hidden",
                            marginBottom: "8px",
                          }}
                        >
                          {imageFiles.slice(0, 3).map((img, i) => (
                            <div
                              key={i}
                              style={{
                                width: "100%",
                                height: "100%",
                                overflow: "hidden",
                              }}
                            >
                              <img
                                src={img}
                                alt=""
                                style={{
                                  width: "100%",
                                  height: "100%",
                                  objectFit: "cover",
                                  display: "block",
                                }}
                              />
                            </div>
                          ))}

                          {imageFiles.length === 2 && <div />}

                          {imageFiles.length === 3 && <div />}

                          {imageFiles.length >= 4 && (
                            <div
                              style={{
                                backgroundColor: "rgba(0,0,0,0.5)",
                                color: "white",
                                fontWeight: "bold",
                                fontSize: "1.5rem",
                                display: "flex",
                                justifyContent: "center",
                                alignItems: "center",
                                userSelect: "none",
                              }}
                            >
                              +{imageFiles.length - 3}
                            </div>
                          )}
                        </div>
                      )}
                    </>
                  )}

                  {/* 리뷰 본문 */}
                  <div
                    className="mb-2 text-muted"
                    style={{
                      fontSize: "0.85rem",
                      lineHeight: "1.0em",
                      display: "-webkit-box",
                      WebkitLineClamp: 2,
                      WebkitBoxOrient: "vertical",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "normal",
                      maxHeight: "2.0em",
                      background: "#f9f9f9",
                      borderRadius: "6px",
                      padding: "0 8px",
                      cursor: "default",
                      userSelect: "text",
                    }}
                  >
                    {r.review}
                  </div>

                  {/* 태그 */}
                  {r.tags?.length > 0 && (
                    <div className="mb-2 d-flex flex-wrap gap-1">
                      {r.tags.slice(0, 3).map((tag) => (
                        <Badge
                          key={tag.id}
                          bg="light"
                          text="dark"
                          className="small"
                          style={{ fontSize: "0.7rem" }}
                        >
                          #{tag.name}
                        </Badge>
                      ))}
                      {r.tags.length > 3 && (
                        <Badge
                          bg="light"
                          text="dark"
                          className="small"
                          style={{ fontSize: "0.7rem" }}
                        >
                          +{r.tags.length - 3}
                        </Badge>
                      )}
                    </div>
                  )}

                  {/* 작성일 */}
                  <div className="mb-2">
                    <small className="text-muted d-flex align-items-center">
                      <FiCalendar size={12} className="me-1" />
                      {r.insertedAt?.split("T")[0]}
                    </small>
                  </div>

                  {/* 좋아요 버튼 */}
                  <div
                    className="d-flex align-items-center gap-2 mt-auto"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <ReviewLikeContainer reviewId={r.id} compact={true} />
                  </div>
                </Card.Body>
              </Card>
            </Col>
          );
        })}
      </Row>
    </Container>
  );
}
