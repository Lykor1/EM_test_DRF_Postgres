let token = localStorage.getItem('token') || null;

function updateAuthStatus() {
    const authStatus = document.getElementById('auth-status');
    authStatus.innerHTML = token ? `Залогинен (Токен: ${token.substring(0, 10)}...)` : 'Не залогинен';
}

updateAuthStatus();

function getCsrfToken() {
    const csrfInput = document.querySelector('input[name="csrfmiddlewaretoken"]');
    return csrfInput ? csrfInput.value : '';
}

async function sendRequest(url, method, data = null, includeToken = true, includeCsrf = false) {
    const headers = {'Content-Type': 'application/json'};
    if (includeToken && token) {
        headers['Authorization'] = `Bearer ${token}`;
    }
    if (includeCsrf) {
        headers['X-CSRFToken'] = getCsrfToken();
    }
    const options = {method, headers};
    if (data) {
        options.body = JSON.stringify(data);
    }
    const response = await fetch(url, options);
    const result = await response.json();
    return {status: response.status, data: result};
}

function displayResponse(elementId, response) {
    const element = document.getElementById(elementId);
    if (response.status >= 200 && response.status < 300) {
        element.className = 'success';
        element.innerHTML = JSON.stringify(response.data, null, 2);
    } else {
        element.className = 'error';
        element.innerHTML = `Ошибка ${response.status}: ${JSON.stringify(response.data, null, 2)}`;
    }
}

document.getElementById('register-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const data = {
        first_name: formData.get('first_name'),
        last_name: formData.get('last_name'),
        patronymic: formData.get('patronymic'),
        email: formData.get('email'),
        password: formData.get('password'),
        password2: formData.get('password2')
    };
    const response = await sendRequest('/api/register/', 'POST', data, false);
    displayResponse('register-response', response);
});

document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const data = {
        email: formData.get('email'),
        password: formData.get('password')
    };
    const response = await sendRequest('/api/login/', 'POST', data, false);
    if (response.status === 200) {
        token = response.data.token;
        localStorage.setItem('token', token);
        updateAuthStatus();
    }
    displayResponse('login-response', response);
});

document.getElementById('logout-btn').addEventListener('click', async () => {
    const response = await sendRequest('/api/logout/', 'POST', null, true, true);
    if (response.status === 200) {
        token = null;
        localStorage.removeItem('token');
        updateAuthStatus();
    }
    displayResponse('logout-response', response);
});

document.getElementById('update-profile-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const data = {};
    if (formData.get('first_name')) data.first_name = formData.get('first_name');
    if (formData.get('last_name')) data.last_name = formData.get('last_name');
    if (formData.get('patronymic')) data.patronymic = formData.get('patronymic');
    if (formData.get('email')) data.email = formData.get('email');
    const response = await sendRequest('/api/profile/update/', 'PATCH', data, true, true);
    displayResponse('update-profile-response', response);
});

document.getElementById('delete-profile-btn').addEventListener('click', async () => {
    console.log("Sending delete profile request"); // Отладка
    const response = await sendRequest('/api/profile/delete/', 'DELETE', null, true, true);
    if (response.status === 200) {
        token = null;
        localStorage.removeItem('token');
        updateAuthStatus();
    }
    displayResponse('delete-profile-response', response);
});

document.getElementById('get-rules-btn').addEventListener('click', async () => {
    const response = await sendRequest('/api/rules/', 'GET');
    displayResponse('rules-response', response);
});

document.getElementById('create-rule-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const data = {
        role: formData.get('role_id'),
        resource: formData.get('resource_id'),
        read_permission: formData.get('read_permission') === 'on',
        read_all_permission: formData.get('read_all_permission') === 'on',
        create_permission: formData.get('create_permission') === 'on',
        update_permission: formData.get('update_permission') === 'on',
        delete_permission: formData.get('delete_permission') === 'on'
    };
    const response = await sendRequest('/api/rules/', 'POST', data, true, true);
    displayResponse('rules-response', response);
});

document.getElementById('get-products-btn').addEventListener('click', async () => {
    const response = await sendRequest('/api/products/', 'GET');
    displayResponse('products-response', response);
});

document.getElementById('create-product-btn').addEventListener('click', async () => {
    const response = await sendRequest('/api/products/', 'POST', null, true, true);
    displayResponse('products-response', response);
});