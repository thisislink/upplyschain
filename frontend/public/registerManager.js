document.addEventListener('DOMContentLoaded', function() {
    // Extract the token from the URL
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');

    // Set the token as the value of the hidden input field
    document.getElementById('registrationToken').value = token;
});

document.getElementById('registerForm').addEventListener('submit', function (event) {
    event.preventDefault();

    var email = document.getElementById('floatingInput').value;
    var password = document.getElementById('floatingPassword').value;

    // Request to backend /login endpoint
    axios.post('/register', { email, password })
        .then(res => {
            window.location.href = '/dashboard';
        })
        .catch(error => {
            console.log('Error: ', error);
            // need to change this to send the message back to the UI
            alert('Login failed. Please check your credentials.');
        });
});
