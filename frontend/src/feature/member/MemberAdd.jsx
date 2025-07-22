import {
  Button,
  Col,
  FormControl,
  FormGroup,
  FormLabel,
  Row,
} from "react-bootstrap";
import { useEffect, useState } from "react";
import axios from "axios";

export function MemberAdd() {
  const [id_, setId_] = useState("");
  const [password1, setPassword1] = useState("");
  const [password2, setPassword2] = useState("");
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [nickName, setNickName] = useState("");
  const [info, setInfo] = useState("");

  function handleSaveClick() {
    axios
      .post("/api/member/add", {
        id_: id_,
        password1: password1,
        email: email,
        name: name,
        nick: nickName,
        info: info,
      })
      .then((res) => {})
      .catch((err) => {})
      .finally(() => {});
  }

  return (
    <Row className="justify-content-center">
      <Col xs={12} md={8} lg={6}>
        <h2 className="mb-4">회원 가입</h2>
        <div>
          <FormGroup className="mb-3" controlId="id_1">
            <FormLabel>아이디</FormLabel>
            <FormControl value={id_} onChange={(e) => setId_(e.target.value)} />
          </FormGroup>
        </div>
        <div>
          <FormGroup className="mb-3" controlId="password1">
            <FormLabel>비밀번호</FormLabel>
            <FormControl
              value={password1}
              onChange={(e) => setPassword1(e.target.value)}
            />
          </FormGroup>
        </div>
        {/*<div>*/}
        {/*  <FormGroup>*/}
        {/*    <FormLabel>비밀번호 확인</FormLabel>*/}
        {/*    <FormControl*/}
        {/*      value={password2}*/}
        {/*      onChange={(e) => setPassword2(e.target.value)}*/}
        {/*    />*/}
        {/*  </FormGroup>*/}
        {/*</div>*/}
        <div>
          <FormGroup className="mb-3" controlId="email1">
            <FormLabel>이메일</FormLabel>
            <FormControl
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </FormGroup>
        </div>
        <hr />
        <div>
          <FormGroup className="mb-3" controlId="name1">
            <FormLabel>이름</FormLabel>
            <FormControl
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </FormGroup>
        </div>
        <div>
          <FormGroup className="mb-3" controlId="nickName1">
            <FormLabel>별명</FormLabel>
            <FormControl
              value={nickName}
              onChange={(e) => setNickName(e.target.value)}
            />
          </FormGroup>
        </div>
        <div>
          <FormGroup className="mb-3" controlId="info1">
            <FormLabel>소개</FormLabel>
            <FormControl
              value={info}
              onChange={(e) => setInfo(e.target.value)}
            />
          </FormGroup>
        </div>
        <div>
          <Button onClick={handleSaveClick}>가입</Button>
        </div>
      </Col>
    </Row>
  );
}
