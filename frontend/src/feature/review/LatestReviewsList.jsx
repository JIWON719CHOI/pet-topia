import React, { useEffect, useRef, useState } from "react";
import axios from "axios";
import {
  Badge,
  Button,
  Card,
  Col,
  Image,
  Row,
  Spinner,
  Container,
} from "react-bootstrap";
import { useNavigate } from "react-router-dom";
import { ReviewLikeContainer } from "../like/ReviewLikeContainer.jsx";

export function LatestReviewsList() {
  const [reviews, setReviews] = useState(null);
  const [displayCount, setDisplayCount] = useState(12); // 처음에 12개 표시
  const [expandedIds, setExpandedIds] = useState([]);
  const [clampedIds, setClampedIds] = useState([]);

  // 신고 관련 상태들
  const [reportModalOpen, setReportModalOpen] = useState(false);
  const [reportReason, setReportReason] = useState("");
  const [reportingReviewId, setReportingReviewId] = useState(null);
  const [reportLoading, setReportLoading] = useState(false);

  const reviewRefs = useRef({});
  const navigate = useNavigate();

  useEffect(() => {
    axios
      .get("/api/review/latest?limit=50")
      .then((res) => setReviews(res.data))
      .catch(() => setReviews([]));
  }, []);

  useEffect(() => {
    if (!reviews) return;
    const newClampedIds = [];
    const visibleReviews = reviews.slice(0, displayCount);
    visibleReviews.forEach((r) => {
      const el = reviewRefs.current[r.id];
      if (!el) return;
      const isClamped = el.scrollHeight > el.clientHeight + 1;
      if (isClamped) newClampedIds.push(r.id);
    });
    setClampedIds(newClampedIds);
  }, [reviews, displayCount]);

  if (!reviews) {
    return (
      <Container className="my-5">
        <div className="text-center">
          <Spinner animation="border" />
        </div>
      </Container>
    );
  }

  if (reviews.length === 0) {
    return (
      <Container className="my-5">
        <h2 className="text-center mb-4 fw-bold">
          <span style={{ color: "#8B4513" }}>📝</span>
          최신 리뷰
        </h2>
        <p className="text-muted text-center">아직 작성된 리뷰가 없습니다.</p>
      </Container>
    );
  }

  const isImageFile = (fileUrl) =>
    /\.(jpg|jpeg|png|gif|webp)$/i.test(fileUrl.split("?")[0]);

  function handleFacilityButton(facilityName, event) {
    event.stopPropagation();
    navigate(`/facility/${encodeURIComponent(facilityName)}`);
  }

  const toggleExpand = (id, event) => {
    event.stopPropagation();
    setExpandedIds((prev) =>
      prev.includes(id) ? prev.filter((i) => i !== id) : [...prev, id],
    );
  };

  const openReportModal = (reviewId, event) => {
    event.stopPropagation();
    setReportingReviewId(reviewId);
    setReportReason("");
    setReportModalOpen(true);
  };

  const closeReportModal = () => {
    setReportModalOpen(false);
    setReportingReviewId(null);
    setReportReason("");
  };

  const submitReport = async () => {
    if (!reportReason.trim()) {
      alert("신고 사유를 입력해주세요.");
      return;
    }
    setReportLoading(true);
    try {
      await axios.post("/api/review/report", {
        reviewId: reportingReviewId,
        reason: reportReason.trim(),
      });
      alert("신고가 접수되었습니다.");
      closeReportModal();
    } catch (error) {
      alert("신고 실패: " + error.message);
    } finally {
      setReportLoading(false);
    }
  };

  const defaultProfileImage = "/user.png";
  const visibleReviews = reviews.slice(0, displayCount);
  const hasMoreReviews = reviews.length > displayCount;

  const loadMoreReviews = () => {
    setDisplayCount((prev) => Math.min(prev + 12, reviews.length));
  };

  return (
    <Container
      className="my-4 p-4"
      style={{
        backgroundColor: "#fafafa",
        borderRadius: "16px",
        boxShadow: "0 8px 24px rgba(0,0,0,0.12)",
      }}
    >
      <h2 className="text-center mb-4 fw-bold">
        <span style={{ color: "#8B4513" }}>📝</span>
        최신 리뷰
        <span className="ms-2 fs-6 text-muted">({reviews.length}개의 리뷰)</span>
      </h2>

      <Row className="g-3">
        {visibleReviews.map((r) => {
          const isExpanded = expandedIds.includes(r.id);
          const imageFiles = r.files?.filter(isImageFile) || [];
          const hasImages = imageFiles.length > 0;
          const facilityInfo = r.petFacility;

          return (
            <Col key={r.id} xs={12} sm={6} md={4} lg={3}>
              <Card
                className="h-100"
                style={{
                  backgroundColor: "#fff",
                  cursor: "pointer",
                  transition: "all 0.2s ease",
                  overflow: "hidden",
                  borderRadius: "12px",
                  border: "1px solid #ddd",
                  boxShadow: "0 4px 10px rgba(0,0,0,0.08)",
                }}
                onClick={() => {
                  if (!facilityInfo || !facilityInfo.id) return;

                  const url = `/facility/${facilityInfo.id}`;
                  const params = new URLSearchParams();
                  params.append("focusReviewId", r.id);

                  navigate(`${url}?${params.toString()}`);
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.transform = "translateY(-4px)";
                  e.currentTarget.style.boxShadow = "0 12px 28px rgba(0,0,0,0.15)";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.transform = "translateY(0)";
                  e.currentTarget.style.boxShadow = "0 4px 10px rgba(0,0,0,0.08)";
                }}
              >
                {hasImages && (
                  <div
                    style={{
                      position: "relative",
                      backgroundColor: "#f8f9fa",
                      height: imageFiles.length > 1 ? "120px" : "150px",
                    }}
                  >
                    {imageFiles.length === 1 ? (
                      <Image
                        src={imageFiles[0]}
                        alt="리뷰 이미지"
                        style={{
                          width: "100%",
                          height: "100%",
                          objectFit: "cover",
                        }}
                      />
                    ) : imageFiles.length === 2 ? (
                      <div className="d-flex" style={{ height: "100%" }}>
                        {imageFiles.slice(0, 2).map((img, idx) => (
                          <div key={idx} style={{ flex: 1, overflow: "hidden" }}>
                            <Image
                              src={img}
                              alt={`리뷰 이미지 ${idx + 1}`}
                              style={{
                                width: "100%",
                                height: "100%",
                                objectFit: "cover",
                              }}
                            />
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="d-flex" style={{ height: "100%" }}>
                        <div style={{ flex: "2", overflow: "hidden" }}>
                          <Image
                            src={imageFiles[0]}
                            alt="리뷰 이미지 1"
                            style={{
                              width: "100%",
                              height: "100%",
                              objectFit: "cover",
                            }}
                          />
                        </div>
                        <div
                          style={{
                            flex: "1",
                            display: "flex",
                            flexDirection: "column",
                          }}
                        >
                          {imageFiles.slice(1, 3).map((img, idx) => (
                            <div
                              key={idx}
                              style={{
                                flex: 1,
                                overflow: "hidden",
                                position: "relative",
                              }}
                            >
                              <Image
                                src={img}
                                alt={`리뷰 이미지 ${idx + 2}`}
                                style={{
                                  width: "100%",
                                  height: "100%",
                                  objectFit: "cover",
                                }}
                              />
                              {idx === 1 && imageFiles.length > 3 && (
                                <div
                                  style={{
                                    position: "absolute",
                                    top: 0,
                                    left: 0,
                                    right: 0,
                                    bottom: 0,
                                    backgroundColor: "rgba(0,0,0,0.6)",
                                    display: "flex",
                                    alignItems: "center",
                                    justifyContent: "center",
                                    color: "white",
                                    fontWeight: "bold",
                                    fontSize: "1.2rem",
                                  }}
                                >
                                  +{imageFiles.length - 3}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                <Card.Body className="p-3 d-flex flex-column">
                  <div className="d-flex justify-content-between align-items-start mb-2">
                    <div
                      className="fw-semibold text-truncate"
                      style={{
                        cursor: "pointer",
                        color: "#495057",
                        fontSize: "0.9rem",
                        maxWidth: "70%",
                      }}
                      onClick={(e) => {
                        e.stopPropagation();
                        if (facilityInfo && facilityInfo.id) {
                          navigate(`/facility/${facilityInfo.id}`);
                        }
                      }}
                      title={facilityInfo?.name || "정보 없음"}
                    >
                      📍 {facilityInfo?.name || "정보 없음"}
                    </div>
                    <div className="text-nowrap">
                      <span style={{ color: "#f0ad4e", fontSize: "0.9rem" }}>
                        {"★".repeat(r.rating)}
                      </span>
                    </div>
                  </div>

                  <div
                    ref={(el) => (reviewRefs.current[r.id] = el)}
                    className={`${!isExpanded ? "line-clamp-2" : ""} mb-2`}
                    style={{
                      fontSize: "0.85rem",
                      lineHeight: "1.4",
                      color: "#666",
                      backgroundColor: "#f9f9f9",
                      borderRadius: "8px",
                      padding: "8px 12px",
                      boxShadow: "inset 0 0 5px rgba(0,0,0,0.05)",
                      flexGrow: 1,
                    }}
                  >
                    {r.review}
                  </div>

                  {clampedIds.includes(r.id) && (
                    <Button
                      variant="link"
                      size="sm"
                      onClick={(e) => toggleExpand(r.id, e)}
                      className="p-0 text-primary"
                      style={{
                        fontSize: "0.75rem",
                        textDecoration: "none",
                      }}
                    >
                      {isExpanded ? "접기" : "더보기"}
                    </Button>
                  )}

                  {r.tags && r.tags.length > 0 && (
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

                  <div
                    className="d-flex justify-content-between align-items-center mt-auto"
                  >
                    <div
                      className="d-flex align-items-center gap-2"
                      onClick={(e) => e.stopPropagation()} // ★ 여기에 이벤트 전파 차단 추가
                    >
                      <ReviewLikeContainer reviewId={r.id} compact={true} />
                      <button
                        onClick={(e) => openReportModal(r.id, e)}
                        title="신고"
                        style={{
                          background: "none",
                          border: "none",
                          padding: "2px",
                          cursor: "pointer",
                          fontSize: "0.9rem",
                          color: "#dc3545",
                          opacity: 0.7,
                        }}
                        onMouseEnter={(e) => (e.target.style.opacity = "1")}
                        onMouseLeave={(e) => (e.target.style.opacity = "0.7")}
                      >
                        🚨
                      </button>
                    </div>
                  </div>
                </Card.Body>
              </Card>
            </Col>
          );
        })}
      </Row>

      {hasMoreReviews && (
        <div className="text-center mt-4">
          <Button
            variant="outline-primary"
            onClick={loadMoreReviews}
            style={{
              padding: "0.75rem 2rem",
              fontWeight: "500",
              borderRadius: "25px",
            }}
          >
            더 많은 리뷰 보기 ({reviews.length - displayCount}개 남음)
          </Button>
        </div>
      )}

      {reportModalOpen && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            width: "100vw",
            height: "100vh",
            backgroundColor: "rgba(0,0,0,0.5)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 1000,
          }}
          onClick={closeReportModal}
        >
          <div
            style={{
              backgroundColor: "white",
              padding: "2rem",
              borderRadius: "12px",
              width: "90%",
              maxWidth: "400px",
              boxShadow: "0 10px 30px rgba(0,0,0,0.2)",
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <h4 className="mb-3">🚨 리뷰 신고하기</h4>
            <textarea
              rows={5}
              placeholder="신고 사유를 구체적으로 작성해주세요."
              value={reportReason}
              onChange={(e) => setReportReason(e.target.value)}
              className="form-control mb-3"
              style={{
                resize: "vertical",
                fontSize: "0.95rem",
              }}
            />
            <small className="text-muted d-block mb-3">
              허위 신고는 제재 대상이 될 수 있습니다.
            </small>
            <div className="d-flex justify-content-end gap-2">
              <button
                onClick={closeReportModal}
                disabled={reportLoading}
                className="btn btn-secondary"
              >
                취소
              </button>
              <button
                onClick={submitReport}
                disabled={reportLoading || !reportReason.trim()}
                className="btn btn-danger"
              >
                {reportLoading ? "신고 중..." : "신고하기"}
              </button>
            </div>
          </div>
        </div>
      )}

      <style>{`
        .line-clamp-2 {
          display: -webkit-box;
          -webkit-line-clamp: 2;
          -webkit-box-orient: vertical;
          overflow: hidden;
        }
      `}</style>
    </Container>
  );
}
