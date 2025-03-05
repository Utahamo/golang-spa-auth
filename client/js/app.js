document.addEventListener('DOMContentLoaded', function () {
    const loginForm = document.getElementById('loginForm');
    const loginSection = document.getElementById('loginSection');
    const dataSection = document.getElementById('dataSection');
    const loginMessage = document.getElementById('loginMessage');
    const userDisplay = document.getElementById('userDisplay');
    const dataDisplay = document.getElementById('dataDisplay');
    const fetchDataButton = document.getElementById('fetchDataButton');
    const logoutButton = document.getElementById('logoutButton');

    // 检查是否已登录
    checkAuthState();

    // 登录表单提交
    loginForm.addEventListener('submit', function (event) {
        event.preventDefault();
        login();
    });

    // 获取数据按钮点击
    fetchDataButton.addEventListener('click', fetchProtectedData);

    // 登出按钮点击
    logoutButton.addEventListener('click', logout);

    // 登录函数
    function login() {
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;

        loginMessage.textContent = '正在登录...';
        loginMessage.className = 'message';

        fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        })
            .then(response => {
                if (!response.ok) {
                    throw new Error('登录失败: ' + response.status);
                }
                return response.json();
            })
            .then(data => {
                localStorage.setItem('token', data.token);
                localStorage.setItem('username', username);
                loginMessage.textContent = '登录成功!';
                loginMessage.className = 'message success';
                setTimeout(showDataSection, 1000);
            })
            .catch(error => {
                console.error('错误:', error);
                loginMessage.textContent = '登录失败，请检查用户名和密码。';
                loginMessage.className = 'message error';
            });
    }

    // 获取受保护数据
    function fetchProtectedData() {
        const token = localStorage.getItem('token');
        if (!token) {
            showLoginSection();
            return;
        }

        dataDisplay.textContent = '加载中...';

        fetch('/api/data', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        })
            .then(response => {
                if (!response.ok) {
                    if (response.status === 401) {
                        throw new Error('授权已过期');
                    }
                    throw new Error('请求失败: ' + response.status);
                }
                return response.json();
            })
            .then(data => {
                dataDisplay.innerHTML = `
                <p><strong>消息:</strong> ${data.message}</p>
                <p><strong>用户:</strong> ${data.username}</p>
                <p><strong>时间:</strong> ${new Date().toLocaleString()}</p>
            `;
            })
            .catch(error => {
                console.error('错误:', error);
                if (error.message === '授权已过期') {
                    localStorage.removeItem('token');
                    localStorage.removeItem('username');
                    showLoginSection();
                } else {
                    dataDisplay.textContent = '获取数据失败: ' + error.message;
                }
            });
    }

    // 登出
    function logout() {
        localStorage.removeItem('token');
        localStorage.removeItem('username');
        showLoginSection();
    }

    // 检查认证状态
    function checkAuthState() {
        const token = localStorage.getItem('token');
        const username = localStorage.getItem('username');

        if (token && username) {
            userDisplay.textContent = username;
            showDataSection();
        } else {
            showLoginSection();
        }
    }

    // 显示数据区域
    function showDataSection() {
        loginSection.style.display = 'none';
        dataSection.style.display = 'block';
        userDisplay.textContent = localStorage.getItem('username');
        dataDisplay.textContent = '';
    }

    // 显示登录区域
    function showLoginSection() {
        loginSection.style.display = 'block';
        dataSection.style.display = 'none';
        loginMessage.textContent = '';
        loginMessage.className = 'message';
    }
});