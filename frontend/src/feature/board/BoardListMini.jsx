import { Alert, Badge, Spinner, Table } from "react-bootstrap";
import { useEffect, useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router";
import { FaRegComments, FaRegImages, FaThumbsUp } from "react-icons/fa";

export function BoardListMini() {
  const [boardList, setBoardList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    setLoading(true);
    setError(null);

    axios
      .get("/api/board/latest")
      .then((res) => {
        // 백엔드 응답이 배열인지 명시적으로 확인
        if (Array.isArray(res.data)) {
          setBoardList(res.data);
        } else {
          // 배열이 아닌 경우 오류로 처리하거나, 빈 배열로 강제 설정
          console.error("API 응답이 배열이 아닙니다:", res.data);
          setError("게시글 목록 형식이 올바르지 않습니다.");
          setBoardList([]); // 안전하게 빈 배열로 설정
        }
      })
      // setBoardList(res.data))
      .catch(() => {
        setError("게시글을 불러오는 중 오류가 발생했습니다.");
      })
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="text-center my-3 text-secondary small">
        <Spinner animation="border" size="sm" /> 불러오는 중...
      </div>
    );
  }

  if (error) {
    return (
      <Alert variant="danger" className="my-3 py-2 px-3 small">
        {error}
      </Alert>
    );
  }

  if (boardList.length === 0) {
    return <p className="text-muted mt-2 small">작성된 글이 없습니다.</p>;
  }

  return (
    <Table
      hover
      responsive
      size="sm"
      className="align-middle text-secondary"
      style={{ fontSize: "0.85rem", tableLayout: "fixed" }}
    >
      <thead>
        <tr className="text-muted">
          <th style={{ width: "40px" }}>#</th>
          <th style={{ width: "40px" }}>
            <FaThumbsUp size={13} />
          </th>
          <th>제목</th>
          <th style={{ width: "80px" }}>작성자</th>
          <th style={{ width: "100px" }}>작성일</th>
        </tr>
      </thead>
      <tbody>
        {boardList.map((board) => (
          <tr
            key={board.id}
            onClick={() => navigate(`/board/${board.id}`)}
            style={{ cursor: "pointer" }}
          >
            <td className="text-muted">{board.id}</td>
            <td className="text-muted">{board.countLike}</td>
            <td
              className="text-dark"
              style={{
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              <div
                className="d-flex gap-2 align-items-center"
                style={{ overflow: "hidden" }}
              >
                <span
                  style={{
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    display: "inline-block",
                    maxWidth: "100%",
                  }}
                >
                  {board.title}
                </span>

                {board.countComment > 0 && (
                  <Badge bg="light" text="dark">
                    <div className="d-flex align-items-center gap-1">
                      <FaRegComments />
                      <span>{board.countComment}</span>
                    </div>
                  </Badge>
                )}
                {board.countFile > 0 && (
                  <Badge bg="info">
                    <div className="d-flex align-items-center gap-1">
                      <FaRegImages />
                      <span>{board.countFile}</span>
                    </div>
                  </Badge>
                )}
              </div>
            </td>
            <td className="text-truncate text-muted" title={board.nickName}>
              {board.nickName}
            </td>
            <td className="text-muted">{board.timesAgo}</td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}
