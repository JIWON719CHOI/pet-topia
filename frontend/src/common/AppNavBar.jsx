// ==================== AppNavBar.jsx ====================
import { Link, NavLink } from "react-router-dom";
import { useContext, useState, useRef, useEffect } from "react";
import { createPortal } from "react-dom";
import { AuthenticationContext } from "./AuthenticationContextProvider.jsx";
import { FaUserCircle } from "react-icons/fa";
import { useNavigate } from "react-router";
import { toast } from "react-toastify";

export function AppNavBar() {
  const { user, logout, isAdmin } = useContext(AuthenticationContext);
  const [showDropdown, setShowDropdown] = useState(false);
  const [showMobileMenu, setShowMobileMenu] = useState(false);
  const [dropdownPosition, setDropdownPosition] = useState({
    top: 0,
    right: 0,
  });
  const dropdownRef = useRef(null);
  const navigate = useNavigate();

  // 드롭다운 위치 계산
  const handleDropdownToggle = (event) => {
    if (!showDropdown) {
      const rect = event.currentTarget.getBoundingClientRect();
      setDropdownPosition({
        top: rect.bottom + window.scrollY,
        right: window.innerWidth - rect.right,
      });
    }
    setShowDropdown(!showDropdown);
  };

  // 모바일 메뉴 토글
  const handleMobileMenuToggle = () => {
    setShowMobileMenu(!showMobileMenu);
  };

  // 외부 클릭 시 드롭다운 닫기
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setShowDropdown(false);
      }
    };

    if (showDropdown) {
      document.addEventListener("mousedown", handleClickOutside);
    }

    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, [showDropdown]);

  // 로그인 시 드롭다운 메뉴에 표시될 타이틀
  const userDropdownTitle = (
    <>
      <div className="user-avatar">
        {user?.nickName?.charAt(0).toUpperCase()}
      </div>
      <span>{user?.nickName}</span>
    </>
  );

  // 커스텀 드롭다운 메뉴 (Portal 사용)
  const CustomDropdown = () => {
    if (!showDropdown) return null;

    return createPortal(
      <div
        ref={dropdownRef}
        className="dropdown-menu-custom show"
        style={{
          position: "absolute",
          top: dropdownPosition.top,
          right: dropdownPosition.right,
        }}
      >
        <Link
          to={`/member?email=${user.email}`}
          className="dropdown-item-custom"
          onClick={() => setShowDropdown(false)}
        >
          마이페이지
        </Link>
        <div className="dropdown-divider"></div>
        <button
          className="dropdown-item-custom danger"
          onClick={() => {
            logout();
            navigate("/login");
            toast("로그아웃되었습니다.");
            setShowDropdown(false);
          }}
        >
          로그아웃
        </button>
      </div>,
      document.body,
    );
  };

  return (
    <nav className="navbar">
      <div className="navbar-container">
        <div className="navbar-inner">
          {/* Logo */}
          <Link to="/" className="navbar-brand">
            <div className="logo-wrapper">
              <span className="logo-text-doc">DOC</span>
              <div className="logo-separator"></div>
              <span className="logo-text-pet">PET</span>
            </div>
          </Link>

          {/* Navigation Menu */}
          <ul className={`nav-menu ${showMobileMenu ? "active" : ""}`}>
            <li className="nav-item">
              <NavLink
                to="/"
                className={({ isActive }) =>
                  `nav-link ${isActive ? "active" : ""}`
                }
                onClick={() => setShowMobileMenu(false)}
              >
                Home
              </NavLink>
            </li>
            <li className="nav-item">
              <NavLink
                to="/kakaoMap"
                className={({ isActive }) =>
                  `nav-link ${isActive ? "active" : ""}`
                }
                onClick={() => setShowMobileMenu(false)}
              >
                Services
              </NavLink>
            </li>
            <li className="nav-item">
              <NavLink
                to="/review/latest"
                className={({ isActive }) =>
                  `nav-link ${isActive ? "active" : ""}`
                }
                onClick={() => setShowMobileMenu(false)}
              >
                Training
              </NavLink>
            </li>
            <li className="nav-item">
              <NavLink
                to="/board/list"
                className={({ isActive }) =>
                  `nav-link ${isActive ? "active" : ""}`
                }
                onClick={() => setShowMobileMenu(false)}
              >
                Blog
              </NavLink>
            </li>
            <li className="nav-item">
              <NavLink
                to="/about"
                className={({ isActive }) =>
                  `nav-link ${isActive ? "active" : ""}`
                }
                onClick={() => setShowMobileMenu(false)}
              >
                About us
              </NavLink>
            </li>
            <li className="nav-item">
              <NavLink
                to="/support"
                className={({ isActive }) =>
                  `nav-link ${isActive ? "active" : ""}`
                }
                onClick={() => setShowMobileMenu(false)}
              >
                Contact
              </NavLink>
            </li>
            {isAdmin() && (
              <li className="nav-item">
                <NavLink
                  to="/admin"
                  className={({ isActive }) =>
                    `nav-link ${isActive ? "active" : ""}`
                  }
                  onClick={() => setShowMobileMenu(false)}
                >
                  관리자
                </NavLink>
              </li>
            )}
          </ul>

          {/* User Actions */}
          <div className="nav-actions">
            {user ? (
              <div className="user-dropdown">
                <button
                  className="user-dropdown-btn"
                  onClick={handleDropdownToggle}
                >
                  {userDropdownTitle}
                </button>
                <CustomDropdown />
              </div>
            ) : (
              <Link to="/login" className="signin-btn">
                SIGN IN 👋
              </Link>
            )}

            {/* Mobile menu toggle */}
            <button
              className="mobile-menu-toggle"
              onClick={handleMobileMenuToggle}
            >
              <div className={`hamburger ${showMobileMenu ? "active" : ""}`}>
                <span></span>
                <span></span>
                <span></span>
              </div>
            </button>
          </div>
        </div>
      </div>
    </nav>
  );
}
