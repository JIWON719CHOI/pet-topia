import React, { useContext, useEffect, useRef, useState } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import { AuthenticationContext } from "../../common/AuthenticationContextProvider.jsx";
import { ReviewLikeContainer } from "../like/ReviewLikeContainer.jsx";
import { FavoriteContainer } from "./FavoriteContainer.jsx";
import { get } from "./data/api.jsx";
import axios from "axios";
import ReviewCard from "../review/ReviewCard.jsx";
import ReviewAdd from "../review/ReviewAdd.jsx";

export function MapDetail() {
  const { id } = useParams();
  const { user } = useContext(AuthenticationContext);
  const [searchParams] = useSearchParams();

  const [facility, setFacility] = useState(null);
  const [reviews, setReviews] = useState([]);
  const [loadingFacility, setLoadingFacility] = useState(true);
  const [loadingReviews, setLoadingReviews] = useState(true);
  const [sortBy, setSortBy] = useState("latest");
  const [isWriting, setIsWriting] = useState(false);

  const reviewRefs = useRef({});

  // 신고 관련 상태
  const [reportModalOpen, setReportModalOpen] = useState(false);
  const [reportReason, setReportReason] = useState("");
  const [reportingReviewId, setReportingReviewId] = useState(null);
  const [reportLoading, setReportLoading] = useState(false);

  // 시설 정보 조회
  const fetchFacility = async () => {
    if (!id) return;
    setLoadingFacility(true);
    try {
      const facilityData = await get(`/pet_facilities/${id}`);
      setFacility(facilityData);
    } catch (err) {
      console.error(`시설 조회 실패 (id=${id}):`, err);
      setFacility(null);
    } finally {
      setLoadingFacility(false);
    }
  };

  // 리뷰 목록 조회 (정렬 옵션 쿼리 파라미터로 전달)
  const fetchReviews = async () => {
    if (!id) return;
    setLoadingReviews(true);
    try {
      const response = await axios.get(`/api/review/facility/${id}`, {
        params: { sort: sortBy },
      });
      setReviews(response.data || []);
    } catch (err) {
      console.error("리뷰 목록 조회 실패:", err);
      setReviews([]);
    } finally {
      setLoadingReviews(false);
    }
  };

  // 리뷰 삭제
  const handleDelete = async (reviewId) => {
    if (!window.confirm("정말 삭제하시겠습니까?")) return;
    try {
      await axios.delete(`/api/review/delete/${reviewId}`, {
        data: { email: user.email },
      });
      alert("삭제 완료");
      fetchReviews();
    } catch (err) {
      console.error("리뷰 삭제 실패:", err);
      alert("삭제 실패: " + (err.response?.data?.message || err.message));
    }
  };

  // 리뷰 작성 모드 토글
  const handleGoToWrite = () => setIsWriting(true);

  // 리뷰 추가/수정 저장
  const handleReviewSaved = (review) => {
    setIsWriting(false);
    fetchReviews();
    console.log(review);
    // const url = `/facility/${id}`;
    const params = new URLSearchParams();
    params.append("focusReviewId", review.id);
  };
  const handleReviewCancel = () => setIsWriting(false);

  // 신고 모달 열기/닫기
  const openReportModal = (reviewId) => {
    setReportingReviewId(reviewId);
    setReportReason("");
    setReportModalOpen(true);
  };
  const closeReportModal = () => {
    setReportModalOpen(false);
    setReportingReviewId(null);
    setReportReason("");
  };

  // 신고 제출
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
      console.error("신고 실패:", error);
      alert("신고 실패: " + (error.response?.data?.message || error.message));
    } finally {
      setReportLoading(false);
    }
  };

  // 평균 평점 계산
  const getAverageRating = () => {
    if (reviews.length === 0) return null;
    const sum = reviews.reduce((acc, r) => acc + r.rating, 0);
    return (sum / reviews.length).toFixed(1);
  };

  // 이미지 파일 판단
  const isImageFile = (fileUrl) => {
    const ext = fileUrl.split(".").pop().split("?")[0];
    return ["jpg", "jpeg", "png", "gif", "webp"].includes(ext.toLowerCase());
  };

  // 모든 이미지 파일만 추출
  const allImagesFromReviews = reviews.flatMap((review) =>
    (review.files || []).filter(isImageFile),
  );

  // 정렬된 리뷰 배열 (최신순 또는 좋아요순)
  const sortedReviews = [...reviews];
  if (sortBy === "likes") {
    sortedReviews.sort((a, b) => (b.likeCount || 0) - (a.likeCount || 0));
  } else {
    sortedReviews.sort((a, b) => {
      const dateA = new Date(a.insertedAt || a.createdAt || 0);
      const dateB = new Date(b.insertedAt || b.createdAt || 0);
      return dateB - dateA;
    });
  }

  // 정렬 혹은 id 변경 시 데이터 다시 불러오기
  useEffect(() => {
    fetchFacility();
    fetchReviews();
  }, [id, sortBy]);

  // 특정 리뷰 하이라이트 및 스크롤
  useEffect(() => {
    const focusReviewId = searchParams.get("focusReviewId");
    if (focusReviewId && reviews.length > 0) {
      const el = reviewRefs.current[focusReviewId];
      if (el) {
        el.scrollIntoView({ behavior: "smooth", block: "center" });
        el.classList.add("review-highlight");
        const timer = setTimeout(
          () => el.classList.remove("review-highlight"),
          2500,
        );
        return () => clearTimeout(timer);
      }
    }
  }, [reviews, searchParams]);

  return (
    <div style={{ padding: "2rem", maxWidth: "1200px", margin: "0 auto" }}>
      {/* 헤더 */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "1.5rem",
        }}
      >
        <h2 style={{ margin: 0 }}>
          {loadingFacility
            ? "불러오는 중..."
            : facility
              ? facility.name
              : "시설 정보 없음"}
        </h2>
        {/*<FavoriteContainer facilityName={facility ? facility.name : ""} />*/}
        {facility && <FavoriteContainer facilityName={facility.name} />}
      </div>

      {/* 시설 정보 */}
      {loadingFacility ? (
        <p>시설 정보 불러오는 중...</p>
      ) : facility ? (
        <div
          style={{
            marginBottom: "2rem",
            padding: "1.5rem",
            backgroundColor: "#f8f9fa",
            borderRadius: "8px",
            border: "1px solid #e9ecef",
          }}
        >
          <div style={{ marginBottom: "0.8rem" }}>
            <strong>📍 도로명 주소:</strong>
            <span>{facility.roadAddress || "정보 없음"}</span>
          </div>
          <div style={{ marginBottom: "0.8rem" }}>
            <strong>📞 전화번호:</strong>
            <span>{facility.phoneNumber || "정보 없음"}</span>
          </div>
          <div style={{ marginBottom: "0.8rem" }}>
            <strong>🌐 홈페이지:</strong>{" "}
            {(() => {
              const homepageRaw = facility?.homepage ?? "";
              const homepage = homepageRaw.trim().toLowerCase();
              const isValid =
                homepage &&
                homepage !== "정보없음" &&
                homepage !== "none" &&
                homepage !== "null";
              return isValid ? (
                <a
                  href={facility.homepage}
                  target="_blank"
                  rel="noreferrer"
                  style={{ color: "#007bff", textDecoration: "none" }}
                >
                  {facility.homepage}
                </a>
              ) : (
                <span>정보 없음</span>
              );
            })()}
          </div>
          <div style={{ marginBottom: "0.8rem" }}>
            <strong>🏖️ 휴무일:</strong>
            <span>{facility.holiday || "정보 없음"}</span>
          </div>
          <div>
            <strong>⏰ 운영시간:</strong>
            <span>{facility.operatingHours || "정보 없음"}</span>
          </div>
        </div>
      ) : (
        <div
          style={{
            padding: "1rem",
            backgroundColor: "#f8d7da",
            color: "#721c24",
            borderRadius: "8px",
            marginBottom: "2rem",
          }}
        >
          시설 정보를 찾을 수 없습니다.
        </div>
      )}

      {/* 리뷰 작성 버튼 */}
      {!isWriting && (
        <div style={{ marginBottom: "2rem" }}>
          {user ? (
            <button
              onClick={handleGoToWrite}
              style={{
                padding: "0.75rem 1.5rem",
                fontSize: "1rem",
                backgroundColor: "#ffc107",
                color: "#212529",
                border: "none",
                borderRadius: "6px",
                cursor: "pointer",
                fontWeight: "500",
                transition: "background-color 0.2s",
              }}
              onMouseOver={(e) =>
                (e.currentTarget.style.backgroundColor = "#ffb300")
              }
              onMouseOut={(e) =>
                (e.currentTarget.style.backgroundColor = "#ffc107")
              }
            >
              ✍️ 리뷰 작성하기
            </button>
          ) : (
            <div
              style={{
                padding: "1rem",
                backgroundColor: "#e7f3ff",
                borderRadius: "6px",
                color: "#004085",
              }}
            >
              💡 로그인한 사용자만 리뷰를 작성할 수 있습니다.
            </div>
          )}
        </div>
      )}

      {/* 리뷰 작성 폼 */}
      {isWriting && facility && (
        <div style={{ marginBottom: "2rem" }}>
          <ReviewAdd
            facility={facility}
            onSave={handleReviewSaved}
            onCancel={handleReviewCancel}
          />
        </div>
      )}

      {/* 평균 평점 */}
      {reviews.length > 0 && (
        <div
          style={{
            marginBottom: "1.5rem",
            padding: "1rem",
            backgroundColor: "#fff3cd",
            borderRadius: "6px",
            display: "flex",
            alignItems: "center",
            gap: "0.5rem",
          }}
        >
          <strong>평균 평점:</strong>
          <span style={{ fontSize: "1.2rem", color: "#f0ad4e" }}>
            {"★".repeat(Math.round(getAverageRating()))}
          </span>
          <span style={{ fontSize: "1.1rem", fontWeight: "600" }}>
            {getAverageRating()} / 5
          </span>
          <span style={{ fontSize: "0.9rem", color: "#666" }}>
            ({reviews.length}개의 리뷰)
          </span>
        </div>
      )}

      {/* 사진/영상 통합 갤러리 */}
      <div style={{ marginTop: "1.5rem" }}>
        <h3 className="mb-3">🎞 사진•영상 📸</h3>
        {loadingReviews ? (
          <p>불러오는 중...</p>
        ) : allImagesFromReviews.length === 0 ? (
          <p>아직 사진•영상이 없습니다.</p>
        ) : (
          <ReviewCard
            review={{ files: allImagesFromReviews }}
            showOnlyImages={true}
          />
        )}
      </div>

      {/* 리뷰 목록 */}
      <div style={{ marginTop: "1.5rem" }}>
        <div
          style={{
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: "1.5rem",
            display: "flex",
          }}
        >
          <h3 style={{ margin: 0 }}>
            📝 리뷰 목록{" "}
            <span
              style={{
                color: "#6c757d",
                fontWeight: "normal",
                fontSize: "1rem",
              }}
            >
              ({reviews.length}개)
            </span>
          </h3>

          {reviews.length > 0 && (
            <div
              style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}
            >
              <label
                htmlFor="sortSelect"
                style={{ fontWeight: "500", margin: 0 }}
              >
                정렬:
              </label>
              <select
                id="sortSelect"
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value)}
                style={{
                  padding: "0.5rem 1rem",
                  fontSize: "1rem",
                  borderRadius: "6px",
                  border: "1px solid #ced4da",
                  backgroundColor: "#fff",
                  cursor: "pointer",
                  minWidth: "120px",
                }}
              >
                <option value="latest">최신순</option>
                <option value="likes">좋아요순</option>
              </select>
            </div>
          )}
        </div>

        {loadingReviews ? (
          <div style={{ textAlign: "center", padding: "2rem" }}>
            <p>리뷰를 불러오는 중...</p>
          </div>
        ) : sortedReviews.length === 0 ? (
          <div
            style={{
              textAlign: "center",
              padding: "3rem",
              backgroundColor: "#f8f9fa",
              borderRadius: "8px",
              color: "#6c757d",
            }}
          >
            <p style={{ fontSize: "1.1rem", margin: 0 }}>
              아직 작성된 리뷰가 없습니다.
            </p>
            {user && (
              <p style={{ marginTop: "0.5rem", fontSize: "0.95rem" }}>
                첫 번째 리뷰를 작성해보세요!
              </p>
            )}
          </div>
        ) : (
          <ul style={{ paddingLeft: 0, listStyle: "none" }}>
            {sortedReviews.map((review) => (
              <li
                key={review.id}
                ref={(el) => (reviewRefs.current[review.id] = el)}
                style={{
                  padding: "1.5rem",
                  marginBottom: "1rem",
                  border: "1px solid #dee2e6",
                  borderRadius: "8px",
                  backgroundColor: "#fff",
                  transition: "all 0.3s ease",
                  boxShadow: "0 1px 3px rgba(0,0,0,0.08)",
                }}
              >
                {/* 평점 */}
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "0.5rem",
                    marginBottom: "1rem",
                    paddingBottom: "1rem",
                    borderBottom: "1px solid #e9ecef",
                  }}
                >
                  <span style={{ color: "#f0ad4e", fontSize: "1.2rem" }}>
                    {"★".repeat(review.rating)}
                    {"☆".repeat(5 - review.rating)}
                  </span>
                  <span
                    style={{
                      fontWeight: "600",
                      color: "#495057",
                      fontSize: "1rem",
                    }}
                  >
                    {review.rating}.0 / 5.0
                  </span>
                </div>

                {/* 리뷰 카드 */}
                <ReviewCard
                  key={review.id}
                  review={review}
                  onUpdate={fetchReviews}
                  onDelete={handleDelete}
                  showOnlyImages={false}
                />

                {/* 액션 버튼 */}
                <div
                  style={{
                    marginTop: "1rem",
                    paddingTop: "1rem",
                    borderTop: "1px solid #e9ecef",
                    display: "flex",
                    alignItems: "center",
                    gap: "1rem",
                  }}
                >
                  <ReviewLikeContainer reviewId={review.id} />
                  <button
                    onClick={() => openReportModal(review.id)}
                    title="리뷰 신고하기"
                    style={{
                      background: "none",
                      border: "1px solid #dc3545",
                      borderRadius: "4px",
                      padding: "0.25rem 0.5rem",
                      cursor: "pointer",
                      fontSize: "0.9rem",
                      color: "#dc3545",
                      display: "flex",
                      alignItems: "center",
                      gap: "0.25rem",
                      transition: "background-color 0.2s",
                    }}
                    onMouseOver={(e) => {
                      e.currentTarget.style.backgroundColor = "#dc3545";
                      e.currentTarget.style.color = "#fff";
                    }}
                    onMouseOut={(e) => {
                      e.currentTarget.style.backgroundColor = "transparent";
                      e.currentTarget.style.color = "#dc3545";
                    }}
                  >
                    🚨 신고
                  </button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* 신고 모달 */}
      {reportModalOpen && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            width: "100vw",
            height: "100vh",
            backgroundColor: "rgba(0, 0, 0, 0.5)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 9999,
          }}
          onClick={closeReportModal}
        >
          <div
            style={{
              backgroundColor: "white",
              padding: "2rem",
              borderRadius: "12px",
              width: "90%",
              maxWidth: "500px",
              boxShadow: "0 10px 40px rgba(0, 0, 0, 0.2)",
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <h3 style={{ marginBottom: "1.5rem", color: "#212529" }}>
              🚨 리뷰 신고하기
            </h3>

            <div style={{ marginBottom: "1.5rem" }}>
              <label
                htmlFor="reportReason"
                style={{
                  display: "block",
                  marginBottom: "0.5rem",
                  fontWeight: "600",
                }}
              >
                신고 사유
              </label>
              <textarea
                id="reportReason"
                rows={4}
                value={reportReason}
                onChange={(e) => setReportReason(e.target.value)}
                style={{
                  width: "100%",
                  padding: "0.75rem",
                  fontSize: "1rem",
                  borderRadius: "6px",
                  border: "1px solid #ced4da",
                  resize: "vertical",
                }}
                placeholder="신고 사유를 자세히 작성해주세요."
              />
            </div>

            <div
              style={{
                display: "flex",
                justifyContent: "flex-end",
                gap: "1rem",
              }}
            >
              <button
                onClick={closeReportModal}
                disabled={reportLoading}
                style={{
                  padding: "0.5rem 1.25rem",
                  fontSize: "1rem",
                  borderRadius: "6px",
                  border: "1px solid #6c757d",
                  backgroundColor: "#e9ecef",
                  cursor: "pointer",
                  transition: "background-color 0.2s",
                }}
                onMouseOver={(e) =>
                  (e.currentTarget.style.backgroundColor = "#dee2e6")
                }
                onMouseOut={(e) =>
                  (e.currentTarget.style.backgroundColor = "#e9ecef")
                }
              >
                취소
              </button>
              <button
                onClick={submitReport}
                disabled={reportLoading}
                style={{
                  padding: "0.5rem 1.25rem",
                  fontSize: "1rem",
                  borderRadius: "6px",
                  border: "none",
                  backgroundColor: "#dc3545",
                  color: "white",
                  cursor: reportLoading ? "not-allowed" : "pointer",
                  transition: "background-color 0.2s",
                }}
                onMouseOver={(e) =>
                  !reportLoading &&
                  (e.currentTarget.style.backgroundColor = "#c82333")
                }
                onMouseOut={(e) =>
                  !reportLoading &&
                  (e.currentTarget.style.backgroundColor = "#dc3545")
                }
              >
                {reportLoading ? "신고 중..." : "신고하기"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
