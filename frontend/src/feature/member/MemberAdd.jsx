// MemberAdd.jsx 수정된 임포트
import {
  Button,
  Card,
  Col,
  FormControl,
  FormGroup,
  FormLabel,
  FormText,
  Row,
  Spinner,
} from "react-bootstrap";
import { useRef, useState } from "react";
import axios from "axios";
import { toast } from "react-toastify";
import { useNavigate } from "react-router";
// Font Awesome 아이콘 (fa)
import { FaPlus } from "react-icons/fa";
// Feather 아이콘 (fi) - 별도로 임포트
import { FiUser, FiMail, FiLock, FiEdit3, FiUserPlus } from "react-icons/fi";

export function MemberAdd() {
  // 입력값 상태 정의
  const [files, setFiles] = useState([]);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [password2, setPassword2] = useState("");
  const [nickName, setNickName] = useState("");
  const [info, setInfo] = useState("");
  const [isProcessing, setIsProcessing] = useState(false);
  const navigate = useNavigate();

  // 숨겨진 파일 인풋을 참조하기 위한 useRef
  const fileInputRef = useRef(null);

  // 정규식 (백엔드와 동일한 조건)
  const emailRegex = /^[\w.-]+@[\w.-]+\.[a-zA-Z]{2,}$/;
  const passwordRegex =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+=-]).{8,}$/;
  const nickRegex = /^[가-힣a-zA-Z0-9]{2,20}$/;

  // 유효성 검사 결과
  const isEmailValid = emailRegex.test(email);
  const isPasswordValid = passwordRegex.test(password);
  const isNickNameValid = nickRegex.test(nickName);
  const isPasswordMatch = password === password2;

  // 버튼 비활성화 조건
  const disabled = !(
    isEmailValid &&
    isPasswordValid &&
    isNickNameValid &&
    isPasswordMatch &&
    !isProcessing
  );

  // 파일 첨부 시 처리하는 함수 (프로필 사진은 하나만)
  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0];
    if (selectedFile) {
      setFiles([
        {
          file: selectedFile,
          previewUrl: URL.createObjectURL(selectedFile),
        },
      ]);
    } else {
      setFiles([]);
    }
  };

  // 프로필 이미지 클릭 시 숨겨진 파일 인풋 클릭
  const handleProfileClick = () => {
    fileInputRef.current.click();
  };

  function handleSaveClick() {
    setIsProcessing(true);

    const formData = new FormData();
    formData.append("email", email);
    formData.append("password", password);
    formData.append("nickName", nickName);
    formData.append("info", info);

    if (files.length > 0) {
      formData.append("files", files[0].file);
    }

    axios
      .post("/api/member/add", formData, {
        headers: { "Content-type": "multipart/form-data" },
      })
      .then((res) => {
        const message = res.data.message;
        if (message) {
          toast(message.text, { type: message.type });
        }
        navigate("/");
      })
      .catch((err) => {
        const message = err.response.data.message;
        if (message) {
          toast(message.text, { type: message.type });
        }
      })
      .finally(() => {
        setIsProcessing(false);
      });
  }

  // 현재 선택된 프로필 이미지의 미리보기 URL
  const currentProfilePreview = files.length > 0 ? files[0].previewUrl : null;

  return (
    <div className="container-fluid py-4">
      <Row className="justify-content-center">
        <Col xs={12} lg={10} xl={8}>
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
              <div className="text-center">
                <h2 className="display-6 fw-bold mb-3">회원 가입</h2>
                <p className="mb-4 opacity-75">
                  프로필 사진을 선택해주세요 (선택사항)
                </p>

                <div className="position-relative d-inline-block">
                  <div
                    className="rounded-circle shadow-lg d-flex align-items-center justify-content-center"
                    onClick={handleProfileClick}
                    style={{
                      width: "150px",
                      height: "150px",
                      backgroundColor: currentProfilePreview
                        ? "transparent"
                        : "rgba(255,255,255,0.2)",
                      border: "4px solid rgba(255,255,255,0.3)",
                      cursor: "pointer",
                      overflow: "hidden",
                    }}
                  >
                    {currentProfilePreview ? (
                      <img
                        src={currentProfilePreview}
                        alt="프로필 미리보기"
                        style={{
                          width: "100%",
                          height: "100%",
                          objectFit: "cover",
                        }}
                      />
                    ) : (
                      <FaPlus
                        size={40}
                        style={{ color: "rgba(255,255,255,0.8)" }}
                      />
                    )}
                  </div>
                </div>

                <FormControl
                  type="file"
                  ref={fileInputRef}
                  onChange={handleFileChange}
                  style={{ display: "none" }}
                  accept="image/*"
                  disabled={isProcessing}
                />

                <p className="mt-3 mb-0 opacity-75 small">
                  클릭해서 프로필 사진을 업로드하세요
                </p>
              </div>
            </Card.Body>
          </Card>

          {/* 계정 정보 입력 카드들 */}
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
                      <FiMail size={20} />
                    </div>
                    <div>
                      <h5 className="mb-0 fw-bold">이메일</h5>
                      <small className="text-muted">Email Address</small>
                    </div>
                  </div>
                  <FormControl
                    type="text"
                    value={email}
                    maxLength={255}
                    placeholder="예: user@example.com"
                    onChange={(e) =>
                      setEmail(e.target.value.replace(/\s/g, ""))
                    }
                    className="bg-light border-0"
                    style={{ borderRadius: "12px" }}
                  />
                  {email && !isEmailValid && (
                    <FormText className="text-danger">
                      이메일 형식이 올바르지 않습니다.
                    </FormText>
                  )}
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
                      <FiUser size={20} />
                    </div>
                    <div>
                      <h5 className="mb-0 fw-bold">별명</h5>
                      <small className="text-muted">Nickname</small>
                    </div>
                  </div>
                  <FormControl
                    value={nickName}
                    maxLength={20}
                    placeholder="2~20자, 한글/영문/숫자만 사용 가능"
                    onChange={(e) =>
                      setNickName(e.target.value.replace(/\s/g, ""))
                    }
                    className="bg-light border-0"
                    style={{ borderRadius: "12px" }}
                  />
                  {nickName && !isNickNameValid && (
                    <FormText className="text-danger">
                      별명은 2~20자, 한글/영문/숫자만 사용할 수 있습니다.
                    </FormText>
                  )}
                </Card.Body>
              </Card>
            </Col>
          </Row>

          {/* 비밀번호 입력 카드들 */}
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
                        backgroundColor: "#ef4444",
                        color: "white",
                      }}
                    >
                      <FiLock size={20} />
                    </div>
                    <div>
                      <h5 className="mb-0 fw-bold">비밀번호</h5>
                      <small className="text-muted">Password</small>
                    </div>
                  </div>
                  <FormControl
                    type="password"
                    value={password}
                    maxLength={255}
                    placeholder="8자 이상, 영문 대/소문자, 숫자, 특수문자 포함"
                    onChange={(e) =>
                      setPassword(e.target.value.replace(/\s/g, ""))
                    }
                    className="bg-light border-0"
                    style={{ borderRadius: "12px" }}
                  />
                  {password && !isPasswordValid && (
                    <FormText className="text-danger">
                      비밀번호는 8자 이상, 영문 대소문자, 숫자, 특수문자를
                      포함해야 합니다.
                    </FormText>
                  )}
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
                        backgroundColor: "#f59e0b",
                        color: "white",
                      }}
                    >
                      <FiLock size={20} />
                    </div>
                    <div>
                      <h5 className="mb-0 fw-bold">비밀번호 확인</h5>
                      <small className="text-muted">Confirm Password</small>
                    </div>
                  </div>
                  <FormControl
                    type="password"
                    value={password2}
                    maxLength={255}
                    placeholder="비밀번호를 다시 입력하세요"
                    onChange={(e) =>
                      setPassword2(e.target.value.replace(/\s/g, ""))
                    }
                    className="bg-light border-0"
                    style={{ borderRadius: "12px" }}
                  />
                  {password2 && !isPasswordMatch && (
                    <FormText className="text-danger">
                      비밀번호가 일치하지 않습니다.
                    </FormText>
                  )}
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
                    backgroundColor: "#8b5cf6",
                    color: "white",
                  }}
                >
                  <FiEdit3 size={20} />
                </div>
                <div>
                  <h5 className="mb-0 fw-bold">자기소개</h5>
                  <small className="text-muted">About Me (선택사항)</small>
                </div>
              </div>
              <FormControl
                as="textarea"
                rows={4}
                value={info}
                maxLength={3000}
                placeholder="자기소개를 입력하세요. 3000자 이내 (선택사항)"
                onChange={(e) => setInfo(e.target.value)}
                className="bg-light border-0"
                style={{
                  resize: "none",
                  borderRadius: "12px",
                }}
              />
            </Card.Body>
          </Card>

          {/* 가입 버튼 카드 */}
          <Card className="border-0 shadow-sm" style={{ borderRadius: "16px" }}>
            <Card.Body className="p-4">
              <Row className="g-3">
                <Col md={6}>
                  <Button
                    variant="outline-secondary"
                    onClick={() => navigate("/")}
                    className="w-100 py-3 fw-medium d-flex align-items-center justify-content-center"
                    style={{ borderRadius: "12px" }}
                    disabled={isProcessing}
                  >
                    취소
                  </Button>
                </Col>
                <Col md={6}>
                  <Button
                    variant="primary"
                    onClick={handleSaveClick}
                    disabled={disabled}
                    className="w-100 py-3 fw-medium d-flex align-items-center justify-content-center"
                    style={{ borderRadius: "12px" }}
                  >
                    {isProcessing ? (
                      <>
                        <Spinner size="sm" className="me-2" />
                        가입 중...
                      </>
                    ) : (
                      <>
                        <FiUserPlus className="me-2" size={18} />
                        가입하기
                      </>
                    )}
                  </Button>
                </Col>
              </Row>
            </Card.Body>
          </Card>
        </Col>
      </Row>
    </div>
  );
}
