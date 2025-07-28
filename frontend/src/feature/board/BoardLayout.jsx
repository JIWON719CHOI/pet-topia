import { Accordion, Carousel, Col, Row, Tab, Tabs } from "react-bootstrap";
import { useState } from "react";
import { BoardListMini } from "./BoardListMini.jsx";
import img1 from "../../assets/01.png";
import img2 from "../../assets/02.jpg";
import img3 from "../../assets/03.jpg";
import img4 from "../../assets/바다.jpg";

export function BoardLayout() {
  const [activeTab, setActiveTab] = useState("2"); // 탭 상태

  return (
    <div>
      {/* Carousel: 이미지 lazy 로딩 및 사이즈 축소 */}
      <Carousel
        className="mb-4"
        style={{ maxHeight: "200px", overflow: "hidden" }}
      >
        <Carousel.Item>
          <img
            className="d-block w-100"
            src={img4}
            alt="1번째 슬라이드"
            loading="lazy"
            style={{
              height: "200px",
              objectFit: "cover",
            }}
          />
          <Carousel.Caption>
            <h6>1번째 슬라이드</h6>
            <p className="d-none d-md-block">시원하지롱</p>
          </Carousel.Caption>
        </Carousel.Item>

        <Carousel.Item>
          <img
            className="d-block w-100"
            src={img2}
            alt="2번째 슬라이드"
            loading="lazy"
            style={{
              height: "200px",
              objectFit: "cover",
            }}
          />
          <Carousel.Caption>
            <h6>2번째 슬라이드</h6>
            <p className="d-none d-md-block">피곤하다</p>
          </Carousel.Caption>
        </Carousel.Item>

        <Carousel.Item>
          <img
            className="d-block w-100"
            src={img3}
            alt="3번째 슬라이드"
            loading="lazy"
            style={{
              height: "200px",
              objectFit: "cover",
            }}
          />
          <Carousel.Caption>
            <h6>3번째 슬라이드</h6>
            <p className="d-none d-md-block">집에갈래</p>
          </Carousel.Caption>
        </Carousel.Item>
      </Carousel>

      {/* Row로 탭과 아코디언을 좌우 배치 */}
      <Row className="my-4">
        {/* 탭 영역 - 왼쪽 */}
        <Col xs={12} md={7}>
          <Tabs
            activeKey={activeTab}
            onSelect={(k) => setActiveTab(k)}
            className="mb-3"
          >
            <Tab eventKey="1" title="공지사항">
              <div className="p-3">공지사항이 없습니다.</div>
            </Tab>
            <Tab eventKey="2" title="최신글">
              <div className="p-3">
                {activeTab === "2" && <BoardListMini />}
              </div>
            </Tab>
          </Tabs>
        </Col>

        {/* 아코디언 영역 - 오른쪽 */}
        <Col xs={12} md={5}>
          <Accordion defaultActiveKey="0">
            <Accordion.Item eventKey="1">
              <Accordion.Header>여기에는</Accordion.Header>
              <Accordion.Body>네.</Accordion.Body>
            </Accordion.Item>
            <Accordion.Item eventKey="2">
              <Accordion.Header>무엇을</Accordion.Header>
              <Accordion.Body>네.</Accordion.Body>
            </Accordion.Item>
            <Accordion.Item eventKey="3">
              <Accordion.Header>만들어야</Accordion.Header>
              <Accordion.Body>나는 비오는 날이 싫다고</Accordion.Body>
            </Accordion.Item>
            <Accordion.Item eventKey="4">
              <Accordion.Header>할까요</Accordion.Header>
              <Accordion.Body>...</Accordion.Body>
            </Accordion.Item>
          </Accordion>
        </Col>
      </Row>
    </div>
  );
}
