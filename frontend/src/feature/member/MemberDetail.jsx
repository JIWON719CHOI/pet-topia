import {
  Button,
  Card,
  Col,
  FormControl,
  FormGroup,
  FormLabel,
  Modal,
  Row,
  Spinner,
} from "react-bootstrap";
import { useContext, useEffect, useState } from "react";
import axios from "axios";
import { useNavigate, useSearchParams } from "react-router";
import { toast } from "react-toastify";
import { AuthenticationContext } from "../../common/AuthenticationContextProvider.jsx";
import {
  FiUser,
  FiMail,
  FiCalendar,
  FiEdit3,
  FiLogOut,
  FiTrash2,
  FiStar,
} from "react-icons/fi";

export function MemberDetail() {
  const [member, setMember] = useState(null);
  const [modalShow, setModalShow] = useState(false);
  const [password, setPassword] = useState("");
  const [tempCode, setTempCode] = useState("");
  const [showFullInfo, setShowFullInfo] = useState(false);
  const { logout, hasAccess } = useContext(AuthenticationContext);
  const [params] = useSearchParams();
  const navigate = useNavigate();

  useEffect(() => {
    axios
      .get(`/api/member?email=${params.get("email")}`)
      .then((res) => {
        setMember(res.data);
      })
      .catch((err) => {
        console.error(err);
        toast.error("회원 정보를 불러오는 중 오류가 발생했습니다.");
      });
  }, [params]);

  function handleDeleteButtonClick() {
    axios
      .delete("/api/member", { data: { email: member.email, password } })
      .then((res) => {
        toast(res.data.message.text, { type: res.data.message.type });
        navigate("/");
        logout();
      })
      .catch((err) => {
        toast(err.response?.data?.message?.text || "오류가 발생했습니다.", {
          type: "danger",
        });
      })
      .finally(() => {
        setModalShow(false);
        setPassword("");
      });
  }

  function handleModalButtonClick() {
    if (isKakao) {
      axios
        .post("/api/member/withdrawalCode", { email: member.email })
        .then((res) => {
          setTempCode(res.data.tempCode);
          setModalShow(true);
        })
        .catch((err) => {
          console.error(err);
          console.log("임시 코드 못 받음");
        })
        .finally(() => setPassword(""));
    } else {
      setModalShow(true);
    }
  }

  function handleLogoutClick() {
    logout();
    navigate("/login");
    toast("로그아웃 되었습니다.", { type: "success" });
  }

  if (!member) {
    return (
      <div className="d-flex justify-content-center my-5">
        <Spinner
          animation="border"
          role="status"
          style={{ color: "#f97316" }}
        />
      </div>
    );
  }

  // 가입일시 포맷 통일
  const formattedInsertedAt = member.insertedAt
    ? member.insertedAt.replace("T", " ").substring(0, 16)
    : "";

  // 프로필 이미지 URL 찾기
  const profileImageUrl = member.files?.find((file) =>
    /\.(jpg|jpeg|png|gif|webp)$/i.test(file),
  );

  // 관리자 여부 확인
  const isAdmin = member.authNames?.includes("admin");

  // 카카오 회원 여부
  const isKakao = member.provider?.includes("kakao");

  return (
    <div className="container-fluid py-4">
      <Row className="justify-content-center">
        <Col xs={12} lg={10} xl={8}>
          {/* 상단 헤더 */}
          <div className="text-center mb-5"></div>

          {/* 메인 프로필 카드 */}
          <Card
            className="border-0 shadow-lg mb-4"
            style={{
              borderRadius: "24px",
              background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
              color: "white",
            }}
          >
            <Card.Body className="p-5">
              <Row className="align-items-center">
                <Col md={4} className="text-center mb-4 mb-md-0">
                  <div className="position-relative d-inline-block">
                    {profileImageUrl ? (
                      <img
                        src={profileImageUrl}
                        alt="프로필 이미지"
                        className="rounded-circle shadow-lg"
                        style={{
                          width: "150px",
                          height: "150px",
                          objectFit: "cover",
                          border: "4px solid rgba(255,255,255,0.3)",
                        }}
                      />
                    ) : (
                      <div
                        className="rounded-circle shadow-lg d-flex align-items-center justify-content-center"
                        style={{
                          width: "150px",
                          height: "150px",
                          backgroundColor: "rgba(255,255,255,0.2)",
                          border: "4px solid rgba(255,255,255,0.3)",
                        }}
                      >
                        <FiUser
                          size={60}
                          style={{ color: "rgba(255,255,255,0.8)" }}
                        />
                      </div>
                    )}
                    {isAdmin && (
                      <span
                        className="position-absolute badge bg-warning text-dark"
                        style={{
                          bottom: "10px",
                          right: "10px",
                          borderRadius: "12px",
                          padding: "6px 12px",
                          fontSize: "0.75rem",
                          fontWeight: "600",
                        }}
                      >
                        관리자
                      </span>
                    )}
                  </div>
                </Col>
                <Col md={8}>
                  <h2 className="display-6 fw-bold mb-2">{member.nickName}</h2>
                  <p className="fs-5 mb-3 opacity-75">
                    <FiMail className="me-2" />
                    {member.email}
                  </p>
                  <p className="mb-3 opacity-75">
                    <FiCalendar className="me-2" />
                    {formattedInsertedAt}에 가입
                  </p>
                  <div className="d-flex flex-wrap gap-2">
                    <span className="badge bg-light text-dark px-3 py-2 rounded-pill">
                      {isKakao ? "카카오 계정" : "일반 계정"}
                    </span>
                    <span className="badge bg-success px-3 py-2 rounded-pill">
                      펫토피아 회원
                    </span>
                  </div>
                </Col>
              </Row>
            </Card.Body>
          </Card>

          {/* 상세 정보 카드들 */}
          <Row className="g-4 mb-4">
            <Col md={6}>
              <Card
                className="h-100 border-0 shadow-sm"
                style={{ borderRadius: "16px" }}
              >
                <Card.Body className="p-4">
                  <div className="d-flex align-items-center mb-3">
                    <div
                      className="rounded-circle me-3 d-flex align-items-center justify-content-center"
                      style={{
                        width: "48px",
                        height: "48px",
                        backgroundColor: "#3b82f6",
                        color: "white",
                      }}
                    >
                      <FiUser size={20} />
                    </div>
                    <div>
                      <h5 className="mb-0 fw-bold">기본 정보</h5>
                      <small className="text-muted">Basic Information</small>
                    </div>
                  </div>
                  <div className="mb-3">
                    <small className="text-muted d-block mb-1">이메일</small>
                    <div className="fw-medium">{member.email}</div>
                  </div>
                  <div>
                    <small className="text-muted d-block mb-1">별명</small>
                    <div className="fw-medium">{member.nickName}</div>
                  </div>
                </Card.Body>
              </Card>
            </Col>
            <Col md={6}>
              <Card
                className="h-100 border-0 shadow-sm"
                style={{ borderRadius: "16px" }}
              >
                <Card.Body className="p-4">
                  <div className="d-flex align-items-center mb-3">
                    <div
                      className="rounded-circle me-3 d-flex align-items-center justify-content-center"
                      style={{
                        width: "48px",
                        height: "48px",
                        backgroundColor: "#10b981",
                        color: "white",
                      }}
                    >
                      <FiCalendar size={20} />
                    </div>
                    <div>
                      <h5 className="mb-0 fw-bold">계정 정보</h5>
                      <small className="text-muted">Account Information</small>
                    </div>
                  </div>
                  <div className="mb-3">
                    <small className="text-muted d-block mb-1">가입일</small>
                    <div className="fw-medium">{formattedInsertedAt}</div>
                  </div>
                  <div>
                    <small className="text-muted d-block mb-1">계정 유형</small>
                    <div className="fw-medium">
                      {isKakao ? "카카오 계정" : "일반 계정"}
                    </div>
                  </div>
                </Card.Body>
              </Card>
            </Col>
          </Row>

          {/* 자기소개 카드 */}
          <Card
            className="border-0 shadow-sm mb-4"
            style={{ borderRadius: "16px" }}
          >
            <Card.Body className="p-4">
              <div className="d-flex align-items-center mb-3">
                <div
                  className="rounded-circle me-3 d-flex align-items-center justify-content-center"
                  style={{
                    width: "48px",
                    height: "48px",
                    backgroundColor: "#f59e0b",
                    color: "white",
                  }}
                >
                  <FiEdit3 size={20} />
                </div>
                <div>
                  <h5 className="mb-0 fw-bold">자기소개</h5>
                  <small className="text-muted">About Me</small>
                </div>
              </div>
              <div
                className="p-3 rounded position-relative"
                style={{
                  backgroundColor: "#f8fafc",
                  minHeight: "80px",
                  lineHeight: "1.6",
                }}
              >
                {member.info ? (
                  <>
                    <div
                      style={{
                        whiteSpace: "pre-wrap",
                        wordBreak: "break-word",
                        maxHeight: showFullInfo ? "none" : "120px",
                        overflow: "hidden",
                        transition: "max-height 0.3s ease",
                      }}
                    >
                      {member.info}
                    </div>
                    {member.info.length > 100 && (
                      <div className="text-center mt-2">
                        <Button
                          variant="link"
                          size="sm"
                          onClick={() => setShowFullInfo(!showFullInfo)}
                          className="text-decoration-none p-0"
                          style={{ fontSize: "0.875rem" }}
                        >
                          {showFullInfo ? "접기" : "더보기"}
                        </Button>
                      </div>
                    )}
                  </>
                ) : (
                  <div className="text-muted">
                    아직 자기소개가 등록되지 않았습니다.
                  </div>
                )}
              </div>
            </Card.Body>
          </Card>

          {/* 액션 버튼들 */}
          {hasAccess(member.email) && (
            <Row className="g-3">
              <Col md={6} lg={3}>
                <Button
                  variant="primary"
                  onClick={() => navigate(`/member/edit?email=${member.email}`)}
                  className="w-100 py-3 fw-medium d-flex align-items-center justify-content-center"
                  style={{ borderRadius: "12px" }}
                >
                  <FiEdit3 className="me-2" size={18} />
                  수정
                </Button>
              </Col>
              <Col md={6} lg={3}>
                <Button
                  variant="success"
                  onClick={() => navigate(`/review/my/${member.id}`)}
                  className="w-100 py-3 fw-medium d-flex align-items-center justify-content-center"
                  style={{ borderRadius: "12px" }}
                >
                  <FiStar className="me-2" size={18} />내 리뷰
                </Button>
              </Col>
              <Col md={6} lg={3}>
                <Button
                  variant="outline-secondary"
                  onClick={handleLogoutClick}
                  className="w-100 py-3 fw-medium d-flex align-items-center justify-content-center"
                  style={{ borderRadius: "12px" }}
                >
                  <FiLogOut className="me-2" size={18} />
                  로그아웃
                </Button>
              </Col>
              <Col md={6} lg={3}>
                <Button
                  variant="outline-danger"
                  onClick={handleModalButtonClick}
                  className="w-100 py-3 fw-medium d-flex align-items-center justify-content-center"
                  style={{ borderRadius: "12px" }}
                >
                  <FiTrash2 className="me-2" size={18} />
                  탈퇴
                </Button>
              </Col>
            </Row>
          )}

          {/* 탈퇴 확인 모달 */}
          <Modal show={modalShow} onHide={() => setModalShow(false)} centered>
            <Modal.Header closeButton className="border-0 pb-2">
              <Modal.Title className="fw-bold">
                {isKakao ? "카카오 회원 탈퇴" : "회원 탈퇴 확인"}
              </Modal.Title>
            </Modal.Header>
            <Modal.Body className="px-4 pb-2">
              <FormGroup controlId="password1">
                <FormLabel className="fw-medium mb-3">
                  {isKakao
                    ? `탈퇴를 원하시면 ${tempCode}를 아래에 작성하세요.`
                    : "탈퇴를 원하시면 암호를 입력하세요"}
                </FormLabel>
                <FormControl
                  type={isKakao ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={
                    isKakao
                      ? "탈퇴를 원하시면 위의 코드를 작성하세요."
                      : "탈퇴를 원하시면 비밀번호를 입력하세요"
                  }
                  autoFocus
                  className="py-3"
                  style={{ borderRadius: "12px" }}
                />
              </FormGroup>
            </Modal.Body>
            <Modal.Footer className="border-0 pt-2">
              <Button
                variant="outline-secondary"
                onClick={() => setModalShow(false)}
                className="px-4 py-2"
                style={{ borderRadius: "10px" }}
              >
                취소
              </Button>
              <Button
                variant="danger"
                onClick={handleDeleteButtonClick}
                className="px-4 py-2"
                style={{ borderRadius: "10px" }}
              >
                탈퇴
              </Button>
            </Modal.Footer>
          </Modal>
        </Col>
      </Row>
    </div>
  );
}
