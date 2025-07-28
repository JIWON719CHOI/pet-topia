import { createContext, useEffect, useState } from "react";
import { jwtDecode } from "jwt-decode";
import axios from "axios";

// Axios 인스턴스 생성 시 baseURL 및 withCredentials 설정
const api = axios.create({
  baseURL: "/api", // 백엔드 API 기본 경로
  withCredentials: true, // 이 부분이 중요!
});

// 토큰 만료되었으면 삭제
const token = localStorage.getItem("token");
if (token) {
  try {
    const decoded = jwtDecode(token);
    if (decoded.exp * 1000 < Date.now()) {
      localStorage.removeItem("token");
    }
  } catch (e) {
    // 토큰이 유효하지 않은 경우 (예: 형식 오류) 삭제
    localStorage.removeItem("token");
    console.error("Invalid token found In localStorage, removing.", e);
  }
}

// Axios 요청 인터셉터
axios.interceptors.request.use((config) => {
  const token = localStorage.getItem("token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
    console.log(
      "DEBUG: Authorization header added:",
      config.headers.Authorization,
    ); // 디버그 로그 추가
  }
  return config;
});

const AuthenticationContext = createContext(null);

export function AuthenticationContextProvider({ children }) {
  const [user, setUser] = useState(null);

  useEffect(() => {
    // 1. URL에서 OAuth2 토큰 확인 (로그인 성공 후 리디렉션 시)
    const urlParams = new URLSearchParams(window.location.search);
    const oauth2Token = urlParams.get("token");

    if (oauth2Token) {
      localStorage.setItem("token", oauth2Token);
      // URL에서 토큰 제거하여 깔끔하게 만듦
      window.history.replaceState({}, document.title, window.location.pathname);
    }

    // 2. localStorage에서 토큰 로드
    const storedToken = localStorage.getItem("token");

    if (storedToken) {
      try {
        const payload = jwtDecode(storedToken);
        console.log("Decoded payload on mount:", payload);

        // 토큰이 유효한지 다시 확인 (exp)
        if (payload.exp * 1000 < Date.now()) {
          console.log("Token expired on mount, removing.");
          localStorage.removeItem("token");
          setUser(null);
          return; // 함수 종료
        }

        // **3. 백엔드 API 호출 시 'api' 인스턴스 사용**
        api
          .get("/member?email=" + payload.sub) // '/api'는 baseURL에 포함되어 있으므로, '/member'만 작성
          .then((res) => {
            const scopes = payload?.scp?.split(" ") ?? [];
            console.log("User scopes on mount:", scopes);
            setUser({
              email: res.data.email,
              nickName: res.data.nickName,
              scope: scopes,
            });
          })
          .catch((error) => {
            console.error("Error fetching user info on mount:", error);
            localStorage.removeItem("token"); // 오류 발생 시 토큰 제거
            setUser(null);
          });
      } catch (e) {
        console.error("Error decoding token on mount:", e);
        localStorage.removeItem("token");
        setUser(null);
      }
    }
  }, []); // 빈 의존성 배열: 컴포넌트 마운트 시 한 번만 실행

  function login(token) {
    // 일반 로그인 시 호출
    localStorage.setItem("token", token);
    const payload = jwtDecode(token);
    console.log("Decoded payload on login:", payload);
    // **4. 백엔드 API 호출 시 'api' 인스턴스 사용**
    api
      .get("/member?email=" + payload.sub)
      .then((res) => {
        const scopes = payload?.scp?.split(" ") ?? [];
        console.log("User scopes on login:", scopes);
        setUser({
          email: res.data.email,
          nickName: res.data.nickName,
          scope: scopes,
        });
      })
      .catch((error) => {
        console.error("Error fetching user info on login:", error);
        localStorage.removeItem("token");
        setUser(null);
      });
  }

  function logout() {
    localStorage.removeItem("token");
    setUser(null);
    // **5. 로그아웃 시 백엔드 로그아웃 API 호출 시 'api' 인스턴스 사용**
    api
      .post("/member/logout") // 백엔드의 logoutUrl과 일치시켜야 함
      .then(() => console.log("Logged out from backend."))
      .catch((error) => console.error("Error during backend logout:", error));
  }

  function hasAccess(email) {
    return user && user.email === email;
  }

  function isAdmin() {
    console.log("Checking admin scope for user:", user);
    return user && user.scope.includes("admin");
  }

  return (
    <AuthenticationContext.Provider
      value={{
        user,
        login,
        logout,
        hasAccess,
        isAdmin,
      }}
    >
      {children}
    </AuthenticationContext.Provider>
  );
}

export { AuthenticationContext };
