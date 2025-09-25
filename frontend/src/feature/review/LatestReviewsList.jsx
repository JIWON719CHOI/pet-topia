// src/feature/review/LatestReviewsList.jsx (FULL REPLACE)
import React, { useContext, useEffect, useMemo, useRef, useState } from "react";
import axios from "axios";
import {
  Badge,
  Button,
  Card,
  Col,
  Container,
  Form,
  Row,
} from "react-bootstrap";
import { useNavigate } from "react-router-dom";
import { ReviewLikeContainer } from "../like/ReviewLikeContainer.jsx";
import ReportModal from "../report/ReportModal.jsx";
import { AuthenticationContext } from "../../common/AuthenticationContextProvider.jsx";
import { toast } from "react-toastify";
import "../../styles/LatestReviewsList.css";

export function LatestReviewsList() {
  const { user } = useContext(AuthenticationContext);
  const [reviews, setReviews] = useState(null);
  const [displayCount, setDisplayCount] = useState(12);

  // --- 검색 상태 & IME 조합 처리 ---
  const [tagFilter, setTagFilter] = useState("");
  const [isComposing, setIsComposing] = useState(false);
  const [stableFilter, setStableFilter] = useState("");

  // 조합이 끝났을 때만 안정 값(stableFilter) 갱신
  useEffect(() => {
    if (!isComposing) setStableFilter(tagFilter);
  }, [tagFilter, isComposing]);

  const normalize = (s) =>
    String(s || "")
      .replace(/^#/, "")
      .trim()
      .toLowerCase();
  const normalizedFilter = normalize(stableFilter);

  const [reportModalOpen, setReportModalOpen] = useState(false);
  const [reportingReviewId, setReportingReviewId] = useState(null);

  const reviewRefs = useRef({});
  const navigate = useNavigate();

  useEffect(() => {
    axios
      .get("/api/review/latest?limit=50")
      .then((res) => setReviews(res.data))
      .catch(() => setReviews([]));
  }, []);

  const isImageFile = (fileUrl) =>
    /\.(jpg|jpeg|png|gif|webp)$/i.test(String(fileUrl || "").split("?")[0]);

  const openReportModal = (review, event) => {
    event.stopPropagation();
    if (!user) {
      toast.info("로그인 후 이용해주세요.");
      return;
    }
    if (user.email === review.memberEmail) {
      toast.error("자신의 리뷰는 신고할 수 없습니다.");
      return;
    }
    setReportingReviewId(review.id);
    setReportModalOpen(true);
  };

  const closeReportModal = () => {
    setReportModalOpen(false);
    setReportingReviewId(null);
  };

  // 필터링은 useMemo로 비용 최소화
  const filteredReviews = useMemo(() => {
    if (!reviews) return [];
    if (!normalizedFilter) return reviews;
    return (
      reviews?.filter((r) =>
        r?.tags?.some((tag) =>
          String(tag?.name || "")
            .toLowerCase()
            .includes(normalizedFilter),
        ),
      ) || []
    );
  }, [reviews, normalizedFilter]);

  const loadMoreReviews = () => {
    setDisplayCount((prev) => Math.min(prev + 12, filteredReviews.length));
  };

  // 로딩
  if (!reviews) {
    return (
      <Container className="latest-reviews-container">
        <div className="loading-brutal">
          <div className="loading-pet-brutal">🐶😺🐭</div>
          <p className="loading-text-brutal">리뷰를 불러오는 중...</p>
        </div>
      </Container>
    );
  }

  // 항상 같은 헤더/입력창 유지
  return (
    <div className="latest-reviews-container">
      <div className="reviews-header">
        <h2 className="reviews-title">📝 최신 리뷰</h2>
        <p className="reviews-subtitle">
          반려동물과 함께한 소중한 경험을 확인해보세요
        </p>
        <span className="reviews-count">{filteredReviews.length}개의 리뷰</span>

        <Form
          className="search-form-brutal"
          onSubmit={(e) => e.preventDefault()} // 엔터 제출 방지
        >
          <Form.Control
            type="text"
            placeholder="태그로 리뷰 검색하기 (예: #카페, #공원)"
            value={tagFilter}
            onChange={(e) => setTagFilter(e.target.value)} // 항상 반영
            onCompositionStart={() => setIsComposing(true)} // 한글 조합 시작
            onCompositionEnd={(e) => {
              setIsComposing(false); // 조합 끝
              setTagFilter(e.currentTarget.value); // (동기화)
            }}
            autoComplete="off"
            className="search-input-brutal"
          />
        </Form>
      </div>

      {/* 본문: 결과가 있으면 그리드, 없으면 빈 상태 */}
      {filteredReviews.length === 0 ? (
        <div className="empty-state-brutal">
          <h3>😔 검색 결과가 없습니다</h3>
          <p>다른 태그로 검색해보거나 검색어를 지워보세요.</p>
        </div>
      ) : (
        <>
          <div className="reviews-grid-container mx-5">
            <Row className="g-3">
              {filteredReviews.slice(0, displayCount).map((r) => {
                const imageFiles = r.files?.filter(isImageFile) || [];
                const facilityInfo = r.petFacility;
                const hasImages = imageFiles.length > 0;

                return (
                  <Col key={r.id} xs={6} sm={6} md={4} lg={3} xl={2}>
                    <Card
                      className="review-card-brutal position-relative"
                      onClick={() => {
                        if (!facilityInfo || !facilityInfo.id) return;
                        const url = `/facility/${facilityInfo.id}`;
                        const params = new URLSearchParams();
                        params.append("focusReviewId", r.id);
                        navigate(`${url}?${params.toString()}`);
                      }}
                    >
                      <Card.Body className="review-card-body">
                        <div className="facility-name-brutal">
                          📍 {facilityInfo?.name || "정보 없음"}
                        </div>

                        <div className="rating-brutal">
                          {"★".repeat(Math.max(0, Number(r.rating) || 0))}
                        </div>

                        {hasImages && (
                          <>
                            {imageFiles.length === 1 && (
                              <Card.Img
                                variant="top"
                                src={imageFiles[0]}
                                loading="lazy"
                                style={{
                                  objectFit: "cover",
                                  height: "100px",
                                  marginBottom: "8px",
                                  borderRadius: "0",
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
                                  height: "100px",
                                  overflow: "hidden",
                                  marginBottom: "8px",
                                  gap: "0",
                                  backgroundColor: "gray",
                                  borderRadius: "0",
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
                                      loading="lazy"
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

                                {imageFiles.length <= 3 && <div />}

                                {imageFiles.length >= 4 && (
                                  <div
                                    style={{
                                      backgroundColor: "gray",
                                      color: "white",
                                      fontWeight: "bold",
                                      fontSize: "1.3rem",
                                      display: "flex",
                                      justifyContent: "center",
                                      alignItems: "center",
                                      userSelect: "none",
                                      boxSizing: "border-box",
                                    }}
                                  >
                                    +{imageFiles.length - 3}
                                  </div>
                                )}
                              </div>
                            )}
                          </>
                        )}

                        <div
                          ref={(el) => (reviewRefs.current[r.id] = el)}
                          className="review-text-brutal"
                        >
                          {r.review}
                        </div>

                        {r.tags?.length > 0 && (
                          <div className="review-tags-brutal">
                            {r.tags.slice(0, 3).map((tag) => (
                              <Badge key={tag.id} className="tag-brutal">
                                #{tag.name}
                              </Badge>
                            ))}
                            {r.tags.length > 3 && (
                              <Badge className="tag-brutal tag-more-brutal">
                                +{r.tags.length - 3}
                              </Badge>
                            )}
                          </div>
                        )}

                        <div
                          className="like-section-brutal"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <div className="like-container">
                            <ReviewLikeContainer
                              reviewId={r.id}
                              compact={true}
                            />
                          </div>

                          <div className="report-container">
                            <Button
                              onClick={(e) => openReportModal(r, e)}
                              className="report-button-brutal"
                              disabled={!user}
                              title={user ? "신고" : "로그인 후 이용 가능"}
                            >
                              🚨
                            </Button>
                          </div>
                        </div>
                      </Card.Body>
                    </Card>
                  </Col>
                );
              })}
            </Row>
          </div>

          {filteredReviews.length > displayCount && (
            <div className="load-more-section mb-5">
              <Button onClick={loadMoreReviews} className="load-more-brutal">
                더 많은 리뷰 보기
                <small>({filteredReviews.length - displayCount}개 남음)</small>
              </Button>
            </div>
          )}
        </>
      )}

      {reportModalOpen && reportingReviewId && (
        <ReportModal reviewId={reportingReviewId} onClose={closeReportModal} />
      )}
    </div>
  );
}
