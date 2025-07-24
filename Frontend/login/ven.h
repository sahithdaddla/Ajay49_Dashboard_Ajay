<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>HRMS Dashboard</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --primary-color: #6366f1;
      --primary-light: #e0e7ff;
      --accent-color: #8b5cf6;
      --dark-color: #1e293b;
      --light-color: #ffffff;
      --gray-100: #f1f5f9;
      --gray-200: #e2e8f0;
      --gray-300: #cbd5e1;
      --gray-700: #334155;
      --header-height: 70px;
      --sidebar-width: 90px;
      --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
      --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
      --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
      --shadow-xl: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
    }

    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    body {
      display: flex;
      flex-direction: column;
      height: 100vh;
      overflow: hidden;
      background-color: var(--gray-100);
      color: var(--dark-color);
      transition: background-color 0.3s ease;
    }

    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      height: var(--header-height);
      padding: 0 20px;
      background-color: var(--light-color);
      box-shadow: var(--shadow-sm);
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      z-index: 100;
      transition: var(--transition);
    }

    .logo-container {
      padding: 10px;
      border-radius: 8px;
      transition: var(--transition);
    }

    .logo {
      height: 40px;
      transition: var(--transition);
    }

    .header-right {
      display: flex;
      align-items: center;
      gap: 16px;
    }

    .search-bar {
      display: flex;
      align-items: center;
      padding: 10px 16px;
      background-color: var(--light-color);
      border-radius: 20px;
      width: 280px;
      border: 1px solid black;
      box-shadow: 0 0 0 2px var(--primary-light), var(--shadow-md);
      transition: var(--transition);
    }

    .search-bar input {
      border: none;
      outline: none;
      padding: 4px;
      background-color: transparent;
      width: 100%;
      font-size: 0.9rem;
      color: black;
    }

    .search-bar input::placeholder {
      color: var(--gray-300);
    }

    .search-bar button {
      background: none;
      border: none;
      cursor: pointer;
      font-size: 1rem;
      color: var(--gray-700);
      transition: var(--transition);
    }

    .search-bar button:hover {
      color: var(--primary-color);
    }

    .header-icon {
      position: relative;
      font-size: 1.3rem;
      cursor: pointer;
      color: var(--gray-700);
      transition: var(--transition);
      padding: 8px;
      border-radius: 8px;
    }

    .header-icon:hover {
      color: var(--primary-color);
      background-color: var(--gray-100);
    }

    .user-profile {
      display: flex;
      align-items: center;
      gap: 12px;
      cursor: pointer;
      padding: 6px 12px;
      border-radius: 8px;
      transition: var(--transition);
    }

    .user-profile:hover {
      background-color: var(--gray-100);
    }

    .user-name {
      font-weight: 500;
      font-size: 0.95rem;
    }

    .user-avatar {
      width: 36px;
      height: 36px;
      border-radius: 50%;
      object-fit: cover;
      border: 2px solid var(--gray-200);
      transition: var(--transition);
    }

    .user-profile:hover .user-avatar {
      border-color: var(--primary-color);
    }

    .main-layout {
      display: flex;
      flex: 1;
      margin-top: var(--header-height);
      height: calc(100vh - var(--header-height));
      transition: var(--transition);
    }

    .sidebar {
      width: var(--sidebar-width);
      background-color: var(--light-color);
      box-shadow: 2px 0 8px rgba(0, 0, 0, 0.1);
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 20px 0;
      overflow-y: auto;
      scrollbar-width: none;
      z-index: 90;
      transition: var(--transition);
    }

    .sidebar::-webkit-scrollbar {
      display: none;
    }

    .nav-item {
      width: 56px;
      height: 56px;
      margin: 8px 0;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      border-radius: 12px;
      text-align: center;
      position: relative;
    }

    .nav-item img {
      width: 22px;
      height: 22px;
    }

    .nav-item span {
      font-size: 0.65rem;
      margin-top: 6px;
      font-weight: 500;
      color: var(--gray-700);
    }

    .nav-item.active {
      background-color: var(--primary-light);
    }

    .nav-item.active img {
      filter: brightness(0) saturate(100%) invert(39%) sepia(98%) saturate(747%) hue-rotate(209deg) brightness(93%) contrast(96%);
    }

    .nav-item.active span {
      color: var(--primary-color);
      font-weight: 600;
    }

    .nav-item.active::after {
      content: '';
      position: absolute;
      left: 0;
      top: 50%;
      transform: translateY(-50%);
      width: 4px;
      height: 24px;
      background-color: var(--primary-color);
      border-radius: 0 4px 4px 0;
    }

    .logout-item {
      width: 56px;
      height: 56px;
      margin: 8px 0;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      border-radius: 12px;
      text-align: center;
      margin-top: auto;
    }

    .logout-item i {
      font-size: 22px;
      color: var(--gray-700);
    }

    .logout-item span {
      font-size: 0.65rem;
      margin-top: 6px;
      font-weight: 500;
      color: var(--gray-700);
    }

    .logout-item:hover {
      background-color: #fee2e2;
    }

    .logout-item:hover i {
      color: #dc3545;
    }

    .logout-item:hover span {
      color: #dc3545;
    }

    .content-area {
      flex: 1;
      background-color: var(--light-color);
      overflow-y: auto;
      border-radius: 16px 0 0 0;
      box-shadow: var(--shadow-sm);
      transition: var(--transition);
      position: relative;
    }

    .content-area iframe {
      width: 100%;
      height: 100%;
      border: none;
      background-color: var(--light-color);
      transition: opacity 0.3s ease;
    }

    /* Dark mode styles */
    body.dark-mode {
      background-color: #0f172a;
      color: #f8fafc;
    }

    body.dark-mode .header,
    body.dark-mode .sidebar {
      background-color: #0f172a;
      box-shadow: 2px 0 8px rgba(0, 0, 0, 0.3);
    }

    body.dark-mode .content-area {
      background-color: #1e293b;
    }

    body.dark-mode .logo-container {
      background-color: transparent;
    }

    body.dark-mode .search-bar {
      background-color: #334155;
      border-color: #475569;
      box-shadow: 0 0 0 2px var(--primary-light), var(--shadow-md);
    }

    body.dark-mode .search-bar input {
      color: #f8fafc;
    }

    body.dark-mode .search-bar input::placeholder {
      color: #94a3b8;
    }

    body.dark-mode .header-icon {
      color: #94a3b8;
    }

    body.dark-mode .header-icon:hover {
      background-color: #334155;
      color: var(--primary-color);
    }

    body.dark-mode .user-profile:hover {
      background-color: #334155;
    }

    body.dark-mode .user-avatar {
      border-color: #475569;
    }

    body.dark-mode .nav-item span,
    body.dark-mode .logout-item span {
      color: #94a3b8;
    }

    body.dark-mode .nav-item.active {
      background-color: #334155;
    }

    body.dark-mode .logout-item:hover {
      background-color: #4b1c1c;
    }

    body.dark-mode .logout-item:hover i {
      color: #f87171;
    }

    body.dark-mode .logout-item:hover span {
      color: #f87171;
    }

    /* Animations */
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(10px); }
      to { opacity: 1; transform: translateY(0); }
    }

    @keyframes slideInRight {
      from { transform: translateX(100%); opacity: 0; }
      to { transform: translateX(0); opacity: 1; }
    }

    @keyframes slideOutRight {
      from { transform: translateX(0); opacity: 1; }
      to { transform: translateX(100%); opacity: 0; }
    }

    /* Alert styles */
    .alert {
      position: fixed;
      top: 20px;
      right: 20px;
      padding: 16px 24px;
      border-radius: 12px;
      color: #fff;
      font-size: 0.95rem;
      display: flex;
      align-items: center;
      gap: 12px;
      box-shadow: var(--shadow-xl);
      z-index: 1000;
      animation: slideInRight 0.4s cubic-bezier(0.16, 1, 0.3, 1),
                 slideOutRight 0.5s cubic-bezier(0.5, 0, 0.75, 0) 2.5s forwards;
      max-width: 350px;
      backdrop-filter: blur(10px);
      border: 1px solid rgba(255, 255, 255, 0.1);
    }

    .alert i {
      font-size: 1.2rem;
    }

    .alert.error {
      background: rgba(239, 68, 68, 0.9);
    }

    .alert.success {
      background: rgba(16, 185, 129, 0.9);
    }

    .alert.warning {
      background: rgba(245, 158, 11, 0.9);
    }

    /* Loading spinner */
    .iframe-loading::after {
      content: '';
      position: absolute;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      width: 40px;
      height: 40px;
      border: 4px solid var(--primary-light);
      border-top-color: var(--primary-color);
      border-radius: 50%;
      animation: spin 1s linear infinite;
      z-index: 10;
    }

    @keyframes spin {
      to { transform: translate(-50%, -50%) rotate(360deg); }
    }

    /* Responsive styles */
    @media (max-width: 1024px) {
      :root {
        --sidebar-width: 80px;
      }

      .search-bar {
        width: 240px;
      }
    }

    @media (max-width: 768px) {
      .header {
        padding: 0 20px;
      }

      .search-bar {
        width: 200px;
        margin-left: 0;
      }

      .logo {
        height: 36px;
      }
    }

    @media (max-width: 640px) {
      .search-bar {
        display: none;
      }

      .user-name {
        display: none;
      }

      .user-profile {
        padding: 0;
      }

      .header-icon {
        padding: 6px;
      }
    }

    /* Loading animation */
    .skeleton {
      background-color: var(--gray-200);
      border-radius: 6px;
      animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
    }

    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.5; }
    }

    body.dark-mode .skeleton {
      background-color: #333333;
    }

    /* Login Page Styles */
    .login-body {
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      margin: 0;
      overflow: hidden;
      font-family: Arial, sans-serif;
      background-color: #f0f2f5;
    }

    .container {
      position: relative;
      width: 100%;
      height: 100vh;
      background-color: rgb(255, 255, 255);
      overflow: hidden;
    }

    .big-circle {
      position: absolute;
      width: 1000px;
      height: 1000px;
      background-color: #0077ff;
      border-radius: 50%;
      top: -500px;
      left: -500px;
      opacity: 0.9;
    }

    .small-circle {
      position: absolute;
      width: 100px;
      height: 100px;
      background-color: #0055cc;
      border-radius: 50%;
      bottom: 20px;
      left: 20px;
      box-shadow: 0 0 15px rgba(255, 255, 255, 0.8), inset 0 0 10px rgba(255, 255, 255, 0.5);
      animation: pulse 2s infinite;
    }

    .overlay-circle {
      position: absolute;
      width: 160px;
      height: 160px;
      background-color: #0055cc;
      border-radius: 50%;
      top: 220px;
      left: 350px;
      box-shadow: 0 0 15px rgba(255, 255, 255, 0.8), inset 0 0 10px rgba(255, 255, 255, 0.5);
      animation: float 3s ease-in-out infinite;
    }

    @keyframes float {
      0%, 100% { transform: translateY(0); }
      50% { transform: translateY(-20px); }
    }

    .right-bottom-circle {
      position: absolute;
      width: 120px;
      height: 120px;
      background-color: #0055cc;
      border-radius: 50%;
      bottom: -42px;
      right: -42px;
      box-shadow: 0 0 15px rgba(255, 255, 255, 0.8), inset 0 0 10px rgba(255, 255, 255, 0.5);
      animation: pulse 2s infinite;
    }

    .welcome-text {
      position: absolute;
      top: 35%;
      left: 2%;
      font-size: 18px;
      font-weight: bold;
      color: rgb(255, 255, 255);
      overflow: hidden;
      white-space: nowrap;
    }

    .welcome-text span {
      font-size: 31px;
      color: rgb(255, 255, 255);
      display: inline-block;
      overflow: hidden;
      white-space: nowrap;
      width: 0;
      animation: typing 3s steps(20, end) forwards;
    }

    .welcome-text p {
      font-size: 18px;
      color: white;
      opacity: 0;
      animation: fadeIn 2s ease-in forwards;
      animation-delay: 3s;
    }

    @keyframes typing {
      from { width: 0; }
      to { width: 370px; }
    }

    .login-container {
      position: absolute;
      top: 50%;
      right: 16%;
      transform: translateY(-50%);
      width: 530px;
      color: black;
      text-align: center;
      background: rgba(255, 255, 255, 0.95);
      padding: 30px;
      border-radius: 10px;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
      box-sizing: border-box;
    }

    .login-container h2 {
      margin-bottom: 10px;
      font-size: 30px;
      color: #0077ff;
    }

    .error-message {
      color: #ff3333;
      font-size: 12px;
      margin-bottom: 20px;
      text-align: center;
      min-height: 14px;
    }

    .input-container {
      position: relative;
      margin-bottom: 25px;
    }

    .input-container input {
      width: 100%;
      padding: 10px 30px 10px 10px;
      border: none;
      border-bottom: 2px solid #000000;
      background: transparent;
      font-size: 16px;
      outline: none;
      transition: border-color 0.3s;
      box-sizing: border-box;
    }

    .input-container input:focus {
      border-bottom-color: #0077ff;
    }

    .input-container label {
      position: absolute;
      top: 10px;
      left: 10px;
      font-size: 18px;
      color: #000000;
      pointer-events: none;
      transition: all 0.3s ease;
    }

    .input-container input:focus + label,
    .input-container input:not(:placeholder-shown) + label {
      top: -10px;
      font-size: 15px;
      color: #0077ff;
    }

    .password-container {
      position: relative;
    }

    .password-container .eye-icon {
      position: absolute;
      right: 10px;
      top: 50%;
      transform: translateY(-50%);
      cursor: pointer;
      color: #0077ff;
      font-size: 18px;
    }

    .login-button {
      width: 100%;
      padding: 12px;
      background-color: #0077ff;
      color: white;
      border: none;
      border-radius: 5px;
      font-size: 18px;
      cursor: pointer;
      transition: background-color 0.3s, transform 0.2s;
      margin-top: 10px;
    }

    .login-button:hover {
      background-color: #0055cc;
      transform: scale(1.02);
    }

    .links {
      margin-top: 15px;
      font-size: 16px;
    }

    .links a {
      color: #0077ff;
      text-decoration: none;
      margin: 0 5px;
      transition: color 0.3s;
    }

    .links a:hover {
      color: #0055cc;
      text-decoration: underline;
    }

    @media (max-width: 1024px) {
      .big-circle {
        width: 800px;
        height: 800px;
        top: -400px;
        left: -400px;
      }

      .overlay-circle {
        top: 180px;
        left: 250px;
        width: 120px;
        height: 120px;
      }

      .login-container {
        right: 10%;
        width: 300px;
        padding: 20px;
      }

      .welcome-text {
        top: 30%;
        left: 5%;
      }

      .welcome-text span {
        font-size: 28px;
      }
    }

    @media (max-width: 768px) {
      .big-circle {
        width: 600px;
        height: 600px;
        top: -300px;
        left: -300px;
      }

      .small-circle {
        width: 80px;
        height: 80px;
        bottom: 10px;
        left: 10px;
      }

      .overlay-circle {
        top: 150px;
        left: 50%;
        transform: translateX(-50%);
        width: 100px;
        height: 100px;
      }

      .right-bottom-circle {
        width: 100px;
        height: 100px;
        bottom: -30px;
        right: -30px;
      }

      .welcome-text {
        top: 20%;
        left: 50%;
        transform: translateX(-50%);
        text-align: center;
      }

      .welcome-text span {
        font-size: 24px;
      }

      .welcome-text p {
        font-size: 16px;
      }

      .login-container {
        top: 50%;
        right: 50%;
        transform: translate(50%, -50%);
        width: 90%;
        max-width: 280px;
        padding: 15px;
      }

      .login-container h2 {
        font-size: 24px;
      }
    }

    @media (max-width: 480px) {
      .big-circle {
        width: 500px;
        height: 500px;
        top: -250px;
        left: -250px;
      }

      .small-circle {
        width: 60px;
        height: 60px;
      }

      .overlay-circle {
        width: 80px;
        height: 80px;
        top: 120px;
      }

      .right-bottom-circle {
        width: 80px;
        height: 80px;
        bottom: -20px;
        right: -20px;
      }

      .welcome-text span {
        font-size: 20px;
      }

      .welcome-text p {
        font-size: 14px;
      }

      .login-container {
        width: 95%;
        padding: 10px;
      }

      .login-container h2 {
        font-size: 20px;
      }

      .input-container input {
        font-size: 14px;
        padding: 8px 25px 8px 8px;
      }

      .input-container label {
        font-size: 16px;
      }

      .eye-icon {
        font-size: 16px;
      }

      .login-button {
        font-size: 16px;
        padding: 10px;
      }

      .error-message {
        font-size: 11px;
      }
    }

    /* Hide/Show Classes */
    .hidden {
      display: none;
    }
  </style>
</head>
<body id="appBody" class="login-body">
  <!-- Login Page Content -->
  <div id="loginView" class="container">
    <div class="big-circle"></div>
    <div class="small-circle"></div>
    <div class="overlay-circle"></div>
    <div class="right-bottom-circle"></div>

    <div class="welcome-text">
      <span>Astrolite Tech Solutions</span>
      <p>For a bright future, we stand together</p>
    </div>

    <div class="login-container">
      <h2>Login</h2>
      <div id="error-message" class="error-message"></div>
      <form id="loginForm">
        <div class="input-container">
          <input type="email" id="email" placeholder=" " required>
          <label for="email">Email</label>
        </div>
        <div class="input-container password-container">
          <input type="password" id="password" placeholder=" " required>
          <label for="password">Password</label>
          <span class="eye-icon" id="eyeIcon"><i class="fas fa-eye"></i></span>
        </div>
        <button type="submit" class="login-button">Login</button>
      </form>
      <div class="links">
        <a href="http://13.60.36.119:8013/">Sign Up</a> | <a href="http://13.60.36.119:8010">Forgot Password?</a>
      </div>
    </div>
  </div>

  <!-- Dashboard Content -->
  <div id="dashboardView" class="hidden">
    <header class="header">
      <div class="logo-container">
        <img src="https://www.astrolitetech.com/assets/uploads/logo.png" alt="Company Logo" class="logo" />
      </div>
      <div class="header-right">
        <div class="search-bar">
          <input type="text" placeholder="Search employees, reports..."/>
          <button><i class="fas fa-search"></i></button>
        </div>
        <div class="header-icon" id="themeToggle" title="Toggle theme">
          <i class="fas fa-moon"></i>
        </div>
        <div class="user-profile">
          <div class="skeleton" style="width:36px;height:36px;border-radius:50%;" id="avatarSkeleton"></div>
          <img src="https://img.icons8.com/fluency/48/user-male-circle.png" alt="User Avatar" class="user-avatar" id="userAvatar" style="display:none;" />
          <span class="user-name" id="userName">Loading...</span>
        </div>
      </div>
    </header>

    <div class="main-layout">
      <div class="sidebar">
        <div class="nav-item active" data-module="attendance" title="Attendance">
          <img src="https://img.icons8.com/color/48/calendar--v1.png" alt="Attendance"/>
          <span>Attendance</span>
        </div>
        <div class="nav-item" data-module="leave" title="Leave Management">
          <img src="https://img.icons8.com/color/48/beach.png" alt="Leave"/>
          <span>Leave</span>
        </div>
        <div class="nav-item" data-module="wfh" title="Work From Home">
          <img src="https://img.icons8.com/color/48/laptop.png" alt="WFH"/>
          <span>WFH</span>
        </div>
        <div class="nav-item" data-module="recruitment" title="Recruitment">
          <img src="https://img.icons8.com/color/48/resume.png" alt="Recruitment"/>
          <span>Recruit</span>
        </div>
        <div class="nav-item" data-module="payslip" title="Payroll">
          <img src="https://img.icons8.com/color/48/money-bag.png" alt="Payroll"/>
          <span>Payroll</span>
        </div>
        <div class="nav-item" data-module="tasks" title="Tasks">
          <img src="https://img.icons8.com/color/48/task-completed.png" alt="Tasks"/>
          <span>Tasks</span>
        </div>
        <div class="nav-item" data-module="offboarding" title="Offboarding">
          <img src="https://img.icons8.com/color/48/exit.png" alt="Offboarding"/>
          <span>Offboard</span>
        </div>
        <div class="nav-item" data-module="helpdesk" title="Help Desk">
          <img src="https://img.icons8.com/color/48/help.png" alt="Help Desk"/>
          <span>Help Desk</span>
        </div>
        <div class="logout-item" id="logoutBtn" title="Logout">
          <i class="fas fa-sign-out-alt"></i>
          <span>Logout</span>
        </div>
      </div>

      <div class="content-area">
        <iframe id="contentFrame" src="http://13.60.36.119:8020/" loading="lazy"></iframe>
      </div>
    </div>
  </div>

  <script>
    document.addEventListener('DOMContentLoaded', async () => {
      const config = {
        apiBaseUrl: 'http://13.60.36.119:3404/api',
        authUrls: {
          login: 'http://13.60.36.119:8012',
          signup: 'http://13.60.36.119:8013/',
          forgotPassword: 'http://13.60.36.119:8010'
        },
        modules: {
          attendance: 'http://3.88.203.125:7100/',
          leave: 'http://13.60.36.119:8037/',
          wfh: 'http://54.166.206.245:8026/',
          recruitment: 'http://3.88.203.125:8024/',
          payslip: 'http://54.166.206.245:8047/',
          tasks: 'http://54.166.206.245:8133/',
          offboarding: 'http://54.166.206.245:8035/',
          helpdesk: 'http://54.166.206.245:8042/'
        },
        sessionCheckInterval: 300000
      };

      const elements = {
        appBody: document.getElementById('appBody'),
        loginView: document.getElementById('loginView'),
        dashboardView: document.getElementById('dashboardView'),
        loginForm: document.getElementById('loginForm'),
        emailInput: document.getElementById('email'),
        passwordInput: document.getElementById('password'),
        errorMessage: document.getElementById('error-message'),
        eyeIcon: document.getElementById('eyeIcon'),
        loginButton: document.querySelector('.login-button'),
        contentFrame: document.getElementById('contentFrame'),
        avatarSkeleton: document.getElementById('avatarSkeleton'),
        userAvatar: document.getElementById('userAvatar'),
        userName: document.getElementById('userName'),
        themeToggle: document.getElementById('themeToggle'),
        navItems: document.querySelectorAll('.nav-item'),
        userProfile: document.querySelector('.user-profile'),
        logoutBtn: document.getElementById('logoutBtn')
      };

      const state = {
        user: null,
        token: null,
        isDarkMode: false,
        isAuthenticated: false
      };

      const utils = {
        showAlert: (type, message) => {
          const alert = document.createElement('div');
          alert.className = `alert ${type}`;
          const icons = {
            success: 'fa-check-circle',
            error: 'fa-exclamation-circle',
            warning: 'fa-exclamation-triangle',
            info: 'fa-info-circle'
          };
          alert.innerHTML = `<i class="fas ${icons[type] || icons.info}"></i> ${message}`;
          document.body.appendChild(alert);
          setTimeout(() => {
            alert.style.animation = 'slideOutRight 0.5s ease-out forwards';
            setTimeout(() => alert.remove(), 500);
          }, 3000);
        },

        handleApiError: (error) => {
          console.error('API Error:', error);
          utils.showAlert('error', error.message || 'An error occurred');
          if (error.status === 401) {
            localStorage.removeItem('token');
            document.cookie = 'accessToken=; Max-Age=0; path=/;';
            document.cookie = 'refreshToken=; Max-Age=0; path=/;';
            state.isAuthenticated = false;
            core.showLoginView();
          }
        },

        getCookie: (name) => {
          const value = `; ${document.cookie}`;
          const parts = value.split(`; ${name}=`);
          if (parts.length === 2) return parts.pop().split(';').shift();
        },

        fetchWithAuth: async (url, options = {}) => {
          try {
            const token = utils.getCookie('accessToken') || localStorage.getItem('token');
            if (!token) {
              throw { status: 401, message: 'No authentication token found' };
            }

            const response = await fetch(`${config.apiBaseUrl}${url}`, {
              ...options,
              headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json',
                ...options.headers
              },
              credentials: 'include'
            });

            if (!response.ok) {
              const errorData = await response.json();
              throw {
                status: response.status,
                message: errorData.error || 'Request failed'
              };
            }

            return await response.json();
          } catch (error) {
            utils.handleApiError(error);
            throw error;
          }
        }
      };

      const core = {
        showLoginView: () => {
          elements.appBody.classList.add('login-body');
          elements.loginView.classList.remove('hidden');
          elements.dashboardView.classList.add('hidden');
          elements.emailInput.focus();
        },

        showDashboardView: () => {
          elements.appBody.classList.remove('login-body');
          elements.loginView.classList.add('hidden');
          elements.dashboardView.classList.remove('hidden');
        },

        verifySession: async () => {
          const token = utils.getCookie('accessToken') || localStorage.getItem('token');
          if (!token) {
            state.isAuthenticated = false;
            core.showLoginView();
            return false;
          }

          try {
            const response = await utils.fetchWithAuth('/profile');
            state.user = response.profile;
            state.token = token;
            state.isAuthenticated = true;

            setTimeout(() => {
              elements.avatarSkeleton.style.display = 'none';
              elements.userAvatar.style.display = 'block';
              elements.userAvatar.src = state.user.profile_image ||
                'https://img.icons8.com/fluency/48/user-male-circle.png';
              elements.userName.textContent = state.user.username || 'User';
              elements.userName.style.opacity = 0;
              setTimeout(() => {
                elements.userName.style.transition = 'opacity 0.3s ease';
                elements.userName.style.opacity = 1;
              }, 50);
            }, 800);

            core.showDashboardView();
            return true;
          } catch (error) {
            localStorage.removeItem('token');
            document.cookie = 'accessToken=; Max-Age=0; path=/;';
            document.cookie = 'refreshToken=; Max-Age=0; path=/;';
            state.isAuthenticated = false;
            core.showLoginView();
            return false;
          }
        },

        initTheme: () => {
          const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
          const savedTheme = localStorage.getItem('theme');
          state.isDarkMode = savedTheme === 'dark' || (!savedTheme && prefersDark);
          
          // Apply theme immediately
          if (state.isDarkMode) {
            document.body.classList.add('dark-mode');
            elements.themeToggle.innerHTML = '<i class="fas fa-sun"></i>';
          } else {
            document.body.classList.remove('dark-mode');
            elements.themeToggle.innerHTML = '<i class="fas fa-moon"></i>';
          }

          elements.themeToggle.addEventListener('click', () => {
            state.isDarkMode = !state.isDarkMode;
            document.body.classList.toggle('dark-mode');
            elements.themeToggle.innerHTML = state.isDarkMode
              ? '<i class="fas fa-sun"></i>'
              : '<i class="fas fa-moon"></i>';
            localStorage.setItem('theme', state.isDarkMode ? 'dark' : 'light');
          });
        },

        initNavigation: () => {
          // Set default iframe source
          elements.contentFrame.src = config.modules.attendance;
          
          elements.navItems.forEach(item => {
            item.addEventListener('click', (e) => {
              e.preventDefault();
              
              // Remove active class from all items
              elements.navItems.forEach(i => i.classList.remove('active'));
              
              // Add active class to clicked item
              item.classList.add('active');
              
              const module = item.getAttribute('data-module');
              const moduleUrl = config.modules[module];
              
              if (moduleUrl) {
                // Show loading state
                elements.contentFrame.style.opacity = '0.5';
                elements.contentFrame.style.transition = 'opacity 0.3s ease';
                
                // Load new content
                elements.contentFrame.src = moduleUrl;
                
                // Handle load completion
                elements.contentFrame.onload = () => {
                  elements.contentFrame.style.opacity = '1';
                };
                
                // Handle errors
                elements.contentFrame.onerror = () => {
                  utils.showAlert('error', `Failed to load ${module} module`);
                  elements.contentFrame.style.opacity = '1';
                };
              }
            });
          });
          
          // Set first nav item as active by default
          if (elements.navItems.length > 0) {
            elements.navItems[0].classList.add('active');
          }
        },

        initSessionChecker: () => {
          setInterval(async () => {
            if (state.isAuthenticated) {
              await core.verifySession();
            }
          }, config.sessionCheckInterval);
        },

        handleLogout: () => {
          fetch(`${config.apiBaseUrl}/logout`, {
            method: 'POST',
            credentials: 'include'
          })
          .then(() => {
            localStorage.removeItem('token');
            document.cookie = 'accessToken=; Max-Age=0; path=/;';
            document.cookie = 'refreshToken=; Max-Age=0; path=/;';
            state.isAuthenticated = false;
            utils.showAlert('success', 'Logged out successfully');
            core.showLoginView();
          })
          .catch(err => {
            utils.handleApiError(err);
          });
        },

        validateForm: () => {
          const email = elements.emailInput.value.trim();
          const password = elements.passwordInput.value;
          elements.errorMessage.textContent = '';
          const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

          if (!email) {
            elements.errorMessage.textContent = 'Email is required';
            return false;
          }
          if (!emailRegex.test(email)) {
            elements.errorMessage.textContent = 'Invalid email format';
            return false;
          }
          if (!password) {
            elements.errorMessage.textContent = 'Password is required';
            return false;
          }
          if (password.length < 8) {
            elements.errorMessage.textContent = 'Password must be at least 8 characters';
            return false;
          }

          return true;
        },

        handleLogin: async (e) => {
          e.preventDefault();
          if (!core.validateForm()) return;

          const email = elements.emailInput.value.trim();
          const password = elements.passwordInput.value;
          elements.loginButton.disabled = true;
          elements.loginButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Logging in...';

          try {
            const response = await fetch(`${config.apiBaseUrl}/login`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              credentials: 'include',
              body: JSON.stringify({ email, password })
            });

            const data = await response.json();

            if (response.ok) {
              if (data.accessToken) {
                localStorage.setItem('token', data.accessToken);
              }
              if (data.user) {
                sessionStorage.setItem('user', JSON.stringify(data.user));
              }
              state.isAuthenticated = true;
              utils.showAlert('success', 'Login successful! Redirecting...');
              await core.verifySession();
            } else {
              elements.errorMessage.textContent = data.error || 'Login failed';
              utils.showAlert('error', data.error || 'Login failed');
              elements.passwordInput.value = '';
            }
          } catch (err) {
            console.error('Login error:', err);
            elements.errorMessage.textContent = 'Error connecting to server';
            utils.showAlert('error', 'Error connecting to server');
          } finally {
            elements.loginButton.disabled = false;
            elements.loginButton.textContent = 'Login';
          }
        },

        togglePassword: () => {
          if (elements.passwordInput.type === 'password') {
            elements.passwordInput.type = 'text';
            elements.eyeIcon.innerHTML = '<i class="fas fa-eye-slash"></i>';
          } else {
            elements.passwordInput.type = 'password';
            elements.eyeIcon.innerHTML = '<i class="fas fa-eye"></i>';
          }
        }
      };

      const init = async () => {
        const isAuthenticated = await core.verifySession();
        if (isAuthenticated) {
          core.initTheme();
          core.initNavigation();
          core.initSessionChecker();
          setTimeout(() => {
            utils.showAlert('success', `Welcome back, ${state.user.username || 'User'}!`);
          }, 1000);
        } else {
          core.showLoginView();
          elements.eyeIcon.addEventListener('click', core.togglePassword);
          elements.loginForm.addEventListener('submit', core.handleLogin);
        }
        elements.logoutBtn.addEventListener('click', core.handleLogout);
      };

      init();

      elements.contentFrame?.addEventListener('error', () => {
        utils.showAlert('error', 'Failed to load module. Please try again later.');
      });
    });
  </script>
</body>
</html>
