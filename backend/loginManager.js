document.getElementById('loginForm').addEventListener('submit', function (event) {
    event.preventDefault();

    var email = document.getElementById('floatingInput').value;
    var password = document.getElementById('floatingPassword').value;

    // AJAX request to your backend /login endpoint
    fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email: email, password: password }),
    })
        .then(response => response.json())
        .then(data => {
            if (data.token) {
                // Login successful, handle accordingly (e.g., redirect or show success message)
                // Example: redirect to dashboard
                window.location.href = '/dashboard';
            } else {
                // Login failed, show error message
                alert('Login failed. Please check your credentials.');
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });
});