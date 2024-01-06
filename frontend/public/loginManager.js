document.getElementById('loginForm').addEventListener('submit', function (event) {
    event.preventDefault();

    var email = document.getElementById('floatingInput').value;
    var password = document.getElementById('floatingPassword').value;
    var rememberMe = document.getElementById('flexCheckDefault').checked

    // Request to backend /login endpoint
    axios.post('/login', { email, password, rememberMe })
        .then(res => {
            window.location.href = '/dashboard';
        })
        .catch(error => {
            console.log('Error: ', error);
            alert('Login failed. Please check your credentials.');
        });
});
