import React, { useContext, useEffect, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import {
  Button,
  Card,
  Col,
  FormControl,
  FormGroup,
  FormLabel,
  FormText,
  Modal,
  Row,
  Spinner,
} from "react-bootstrap";
import axios from "axios";
import { toast } from "react-toastify";
import { AuthenticationContext } from "../../common/AuthenticationContextProvider.jsx";
import { FaPlus, FaTrashAlt } from "react-icons/fa";
import {
  FiUser,
  FiMail,
  FiCalendar,
  FiEdit3,
  FiSave,
  FiX,
  FiLock,
} from "react-icons/fi";

export function MemberEdit() {
  // 상태 정의
  const [member, setMember] = useState(null);
  const [modalShow, setModalShow] = useState(false);
  const [passwordModalShow, setPasswordModalShow] = useState(false);
  const [password, setPassword] = useState("");
  const [oldPassword, setOldPassword] = useState("");
  const [newPassword1, setNewPassword1] = useState("");
  const [newPassword2, setNewPassword2] = useState("");
  const [currentProfileUrls, setCurrentProfileUrls] = useState([]);
  const [newProfileFiles, setNewProfileFiles] = useState([]);
  const [deleteProfileFileNames, setDeleteProfileFileNames] = useState([]);
  const [tempCode, setTempCode] = useState("");

  const [params] = useSearchParams();
  const navigate = useNavigate();
  const { hasAccess, updateUser } = useContext(AuthenticationContext);
  const isSelf = member ? hasAccess(member.email) : false;
  const fileInputRef = useRef(null);

  // 정규식
  const passwordRegex =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+=-]).{8,}$/;
  const nickRegex = /^[가-힣a-zA-Z0-9]{2,20}$/;

  // 최초 회원 정보 로딩
  useEffect(() => {
    axios
      .get(`/api/member?email=${params.get("email")}`)
      .then((res) => {
        setMember(res.data);
        const existingImages = res.data.files?.filter((fileUrl) =>
          /\.(jpg|jpeg|png|gif|webp)$/i.test(fileUrl),
        );
        setCurrentProfileUrls(existingImages || []);
        setNewProfileFiles([]);
        setDeleteProfileFileNames([]);
      })
      .catch((err) => {
        console.error("회원 정보 로딩 실패", err);
        toast.error("회원 정보를 불러오는 중 오류가 발생했습니다.");
      });
  }, [params]);

  useEffect(() => {
    return () => {
      newProfileFiles.forEach((file) => {
        if (file instanceof File && file.previewUrl) {
          URL.revokeObjectURL(file.previewUrl);
        }
      });
    };
  }, [newProfileFiles]);

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

  // 유효성
  const isNickNameValid = nickRegex.test(member.nickName);
  const isPasswordValid = passwordRegex.test(newPassword1);
  const isPasswordMatch = newPassword1 === newPassword2;

  // 버튼 비활성화
  const isSaveDisabled = !isNickNameValid;
  const isChangePasswordDisabled =
    !oldPassword ||
    !newPassword1 ||
    !newPassword2 ||
    !isPasswordValid ||
    !isPasswordMatch;

  // 프로필 이미지 클릭 시 숨겨진 파일 input 활성화
  const handleProfileClick = () => {
    if (isSelf && fileInputRef.current) {
      fileInputRef.current.click();
    }
  };

  // 파일 선택 시 처리하는 함수
  const handleFileChange = (e) => {
    const selectedFiles = Array.from(e.target.files);
    if (selectedFiles.length > 0) {
      const file = selectedFiles[0];
      file.previewUrl = URL.createObjectURL(file);
      setNewProfileFiles([file]);

      if (
        currentProfileUrls.length > 0 &&
        deleteProfileFileNames.length === 0
      ) {
        const fileName = currentProfileUrls[0].split("/").pop();
        setDeleteProfileFileNames([fileName]);
      } else if (
        currentProfileUrls.length === 0 &&
        deleteProfileFileNames.length > 0
      ) {
        setDeleteProfileFileNames([]);
      }
    }
  };

  // 프로필 이미지 제거 버튼 클릭 시 처리하는 함수
  const handleRemoveProfile = (fileUrlToRemove) => {
    if (fileUrlToRemove && fileUrlToRemove.startsWith("blob:")) {
      URL.revokeObjectURL(fileUrlToRemove);
    }

    setCurrentProfileUrls((prevUrls) => {
      const remainingUrls = prevUrls.filter((url) => url !== fileUrlToRemove);
      return remainingUrls;
    });

    const fileName = fileUrlToRemove.split("/").pop();
    setDeleteProfileFileNames((prevDelete) => [...prevDelete, fileName]);

    newProfileFiles.forEach((file) => {
      if (file instanceof File && file.previewUrl) {
        URL.revokeObjectURL(file.previewUrl);
      }
    });
    setNewProfileFiles([]);

    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  // 가입일시 포맷 통일
  const formattedInsertedAt = member.insertedAt
    ? member.insertedAt.replace("T", " ").substring(0, 16)
    : "";

  // 정보 수정 요청
  const handleSaveButtonClick = () => {
    if (password.trim() === "") {
      toast.error("비밀번호를 입력해주세요.");
      return;
    }

    const formData = new FormData();
    formData.append("email", member.email);
    formData.append("nickName", member.nickName);
    formData.append("info", member.info || "");
    formData.append("password", password);

    newProfileFiles.forEach((file) => {
      formData.append("profileFiles", file);
    });

    deleteProfileFileNames.forEach((name) => {
      formData.append("deleteProfileFileNames", name);
    });

    axios
      .put(`/api/member`, formData, {
        headers: { "Content-Type": "multipart/form-data" },
      })
      .then((res) => {
        const message = res.data.message;
        if (message) toast(message.text, { type: message.type });
        updateUser({ nickName: member.nickName });
        navigate(`/member?email=${member.email}`);
      })
      .catch((err) => {
        const message = err.response?.data?.message;
        if (message) toast(message.text, { type: message.type });
      })
      .finally(() => {
        setModalShow(false);
        setPassword("");
      });
  };

  // 비밀번호 변경 요청
  const handleChangePasswordButtonClick = () => {
    axios
      .put(`/api/member/changePassword`, {
        email: member.email,
        oldPassword,
        newPassword: newPassword1,
      })
      .then((res) => {
        const message = res.data.message;
        if (message) toast(message.text, { type: message.type });
        setPasswordModalShow(false);
        setOldPassword("");
        setNewPassword1("");
        setNewPassword2("");
      })
      .catch((err) => {
        const message = err.response?.data?.message;
        if (message) toast(message.text, { type: message.type });
      });
  };

  // 모든 프로필 이미지 (기존 + 새로 선택된)
  const allProfileImages = [
    ...currentProfileUrls,
    ...newProfileFiles.map((f) => f.previewUrl),
  ];
  const displayProfileImage =
    allProfileImages.length > 0 ? allProfileImages[0] : null;

  const isAdmin = member.authNames?.includes("admin");
  const isKakao = member.provider?.includes("kakao");

  function handleModalShowClick() {
    if (isKakao) {
      axios
        .post("/api/member/withdrawalCode", { email: member.email })
        .then((res) => {
          setTempCode(res.data.tempCode);
          setModalShow(true);
        })
        .catch((err) => {
          console.error(err);
          console.log("임시 코드 발급 안 됨");
        })
        .finally(() => setPassword(""));
    } else {
      setModalShow(true);
    }
  }

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
                    <div
                      className="rounded-circle shadow-lg d-flex align-items-center justify-content-center"
                      onClick={handleProfileClick}
                      style={{
                        width: "150px",
                        height: "150px",
                        backgroundColor: displayProfileImage
                          ? "transparent"
                          : "rgba(255,255,255,0.2)",
                        border: "4px solid rgba(255,255,255,0.3)",
                        cursor: isSelf ? "pointer" : "default",
                        overflow: "hidden",
                      }}
                    >
                      {displayProfileImage ? (
                        <img
                          src={displayProfileImage}
                          alt="프로필 이미지"
                          style={{
                            width: "100%",
                            height: "100%",
                            objectFit: "cover",
                          }}
                        />
                      ) : (
                        <FiUser
                          size={60}
                          style={{ color: "rgba(255,255,255,0.8)" }}
                        />
                      )}
                    </div>
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

                  <FormControl
                    type="file"
                    ref={fileInputRef}
                    onChange={handleFileChange}
                    style={{ display: "none" }}
                    accept="image/*"
                    disabled={!isSelf}
                    onClick={(e) => {
                      e.target.value = null;
                    }}
                  />

                  {isSelf && displayProfileImage && (
                    <Button
                      variant="outline-light"
                      size="sm"
                      onClick={() => handleRemoveProfile(displayProfileImage)}
                      className="mt-3 d-flex align-items-center gap-2 mx-auto"
                      style={{ borderRadius: "20px" }}
                    >
                      <FaTrashAlt size={14} /> 사진 제거
                    </Button>
                  )}
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
                      <FiMail size={20} />
                    </div>
                    <div>
                      <h5 className="mb-0 fw-bold">이메일</h5>
                      <small className="text-muted">Email Address</small>
                    </div>
                  </div>
                  <FormControl
                    disabled
                    value={member.email}
                    className="bg-light border-0"
                    style={{ color: "#6c757d" }}
                  />
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
                    value={member.nickName}
                    maxLength={20}
                    placeholder="2~20자, 한글/영문/숫자만 사용 가능"
                    onChange={(e) =>
                      setMember({
                        ...member,
                        nickName: e.target.value.replace(/\s/g, ""),
                      })
                    }
                    className="bg-light border-0"
                    disabled={!isSelf}
                  />
                  {member.nickName && !isNickNameValid && (
                    <FormText className="text-danger">
                      별명은 2~20자, 한글/영문/숫자만 사용할 수 있습니다.
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
              <FormControl
                as="textarea"
                value={member.info || ""}
                maxLength={3000}
                onChange={(e) => setMember({ ...member, info: e.target.value })}
                className="bg-light border-0"
                style={{
                  minHeight: "120px",
                  resize: "none",
                  borderRadius: "12px",
                }}
                disabled={!isSelf}
                placeholder="자기소개를 입력하세요..."
              />
            </Card.Body>
          </Card>

          {/* 액션 버튼들 */}
          {hasAccess(member.email) && (
            <Row className="g-3">
              <Col md={6} lg={3}>
                <Button
                  variant="outline-secondary"
                  onClick={() => navigate(-1)}
                  className="w-100 py-3 fw-medium d-flex align-items-center justify-content-center"
                  style={{ borderRadius: "12px" }}
                >
                  <FiX className="me-2" size={18} />
                  취소
                </Button>
              </Col>
              <Col md={6} lg={3}>
                <Button
                  variant="primary"
                  disabled={isSaveDisabled}
                  onClick={handleModalShowClick}
                  className="w-100 py-3 fw-medium d-flex align-items-center justify-content-center"
                  style={{ borderRadius: "12px" }}
                >
                  <FiSave className="me-2" size={18} />
                  저장
                </Button>
              </Col>
              {!isKakao && (
                <Col md={6} lg={3}>
                  <Button
                    variant="outline-info"
                    onClick={() => setPasswordModalShow(true)}
                    className="w-100 py-3 fw-medium d-flex align-items-center justify-content-center"
                    style={{ borderRadius: "12px" }}
                  >
                    <FiLock className="me-2" size={18} />
                    암호 변경
                  </Button>
                </Col>
              )}
            </Row>
          )}

          {/* 회원 정보 수정 확인 모달 */}
          <Modal show={modalShow} onHide={() => setModalShow(false)} centered>
            <Modal.Header closeButton className="border-0 pb-2">
              <Modal.Title className="fw-bold">회원 정보 수정 확인</Modal.Title>
            </Modal.Header>
            <Modal.Body className="px-4 pb-2">
              <FormGroup controlId="password1">
                <FormLabel className="fw-medium mb-3">
                  {isKakao
                    ? `정보 수정을 원하시면 ${tempCode}를 입력하세요.`
                    : "정보 수정을 원하시면 암호를 입력하세요."}
                </FormLabel>
                <FormControl
                  type={isKakao ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={
                    isKakao
                      ? "정보 수정을 원하시면 위의 코드를 입력하세요."
                      : "정보 수정을 원하시면 현재 비밀번호를 입력하세요."
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
                variant="primary"
                onClick={handleSaveButtonClick}
                className="px-4 py-2"
                style={{ borderRadius: "10px" }}
              >
                저장
              </Button>
            </Modal.Footer>
          </Modal>

          {/* 비밀번호 변경 모달 */}
          <Modal
            show={passwordModalShow}
            onHide={() => setPasswordModalShow(false)}
            centered
          >
            <Modal.Header closeButton className="border-0 pb-2">
              <Modal.Title className="fw-bold">비밀번호 변경</Modal.Title>
            </Modal.Header>
            <Modal.Body className="px-4 pb-2">
              <FormGroup className="mb-3" controlId="password2">
                <FormLabel className="fw-medium">현재 비밀번호</FormLabel>
                <FormControl
                  type="password"
                  value={oldPassword}
                  onChange={(e) => setOldPassword(e.target.value)}
                  className="py-3"
                  style={{ borderRadius: "12px" }}
                />
              </FormGroup>

              <FormGroup className="mb-3" controlId="password3">
                <FormLabel className="fw-medium">변경할 비밀번호</FormLabel>
                <FormControl
                  type="password"
                  value={newPassword1}
                  maxLength={255}
                  placeholder="8자 이상, 영문 대/소문자, 숫자, 특수문자 포함"
                  onChange={(e) => setNewPassword1(e.target.value)}
                  className="py-3"
                  style={{ borderRadius: "12px" }}
                />
                {newPassword1 && !isPasswordValid && (
                  <FormText className="text-danger">
                    비밀번호는 8자 이상, 영문 대소문자, 숫자, 특수문자를
                    포함해야 합니다.
                  </FormText>
                )}
              </FormGroup>

              <FormGroup className="mb-3" controlId="password4">
                <FormLabel className="fw-medium">
                  변경할 비밀번호 확인
                </FormLabel>
                <FormControl
                  type="password"
                  value={newPassword2}
                  maxLength={255}
                  placeholder="변경할 비밀번호를 다시 입력하세요"
                  onChange={(e) => setNewPassword2(e.target.value)}
                  className="py-3"
                  style={{ borderRadius: "12px" }}
                />
                {newPassword2 && !isPasswordMatch && (
                  <FormText className="text-danger">
                    비밀번호가 일치하지 않습니다.
                  </FormText>
                )}
              </FormGroup>
            </Modal.Body>
            <Modal.Footer className="border-0 pt-2">
              <Button
                variant="outline-secondary"
                onClick={() => setPasswordModalShow(false)}
                className="px-4 py-2"
                style={{ borderRadius: "10px" }}
              >
                취소
              </Button>
              <Button
                variant="primary"
                onClick={handleChangePasswordButtonClick}
                disabled={isChangePasswordDisabled}
                className="px-4 py-2"
                style={{ borderRadius: "10px" }}
              >
                변경
              </Button>
            </Modal.Footer>
          </Modal>
        </Col>
      </Row>
    </div>
  );
}
