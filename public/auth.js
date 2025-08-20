// public/auth.js

const registerForm = document.getElementById('register-form');
const loginForm = document.getElementById('login-form');
const messageEl = document.getElementById('message');

registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('register-username').value;
    const password = document.getElementById('register-password').value;
    
    const res = await fetch('/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
    });

    const data = await res.json();
    if (res.ok) {
        messageEl.textContent = 'Registration successful! Please log in.';
        messageEl.style.color = 'green';
    } else {
        messageEl.textContent = data.message;
        messageEl.style.color = 'red';
    }
});

loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;

    const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
    });
    
    const data = await res.json();
    if (res.ok) {
        // Login successful, save the token and redirect
        sessionStorage.setItem('token', data.token);
        window.location.href = '/diary.html'; // Redirect to the diary page
    } else {
        messageEl.textContent = data.message;
        messageEl.style.color = 'red';
    }
});