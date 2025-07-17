/**
 * Handles the submission of the login form.
 * It prevents the default form submission, displays a loading spinner,
 * and sends the form data to the 'api/login.php' endpoint.
 *
 * @param {Event} event The form submission event.
 */
function handleLogin(event) {
    event.preventDefault();

    const form = event.target;
    const loginButton = form.querySelector('button');
    const btnText = loginButton.querySelector('.btn-text');
    const btnSpinner = loginButton.querySelector('.btn-spinner');
    const btnIcon = loginButton.querySelector('svg');
    const messageDiv = document.getElementById('loginMessage');

    btnText.style.display = 'none';
    btnIcon.style.display = 'none';
    btnSpinner.style.display = 'flex';
    loginButton.disabled = true;

    const formData = new FormData(form);

    fetch('api/login.php', {
        method: 'POST',
        body: formData
    })
        .then(res => res.json().then(data => ({ ok: res.ok, body: data })))
        .then(({ ok, body }) => {
            messageDiv.textContent = body.message;

            if (ok && body.success) {
                messageDiv.style.color = 'green';
                form.reset();
                if (body.jwt) localStorage.setItem('jwt', body.jwt);
                showSuccess();
            } else messageDiv.style.color = 'red';
        })
        .catch(error => {
            console.error('Login error:', error);
            messageDiv.textContent = 'An unexpected network error occurred.';
            messageDiv.style.color = 'red';
        })
        .finally(() => {
            btnText.style.display = '';
            btnIcon.style.display = '';
            btnSpinner.style.display = 'none';
        });
}

/**
 * Handles the submission of the registration form.
 * It prevents the default form submission, shows a loading state,
 * and sends the form data to the 'api/register.php' endpoint.
 *
 * @param {Event} event The form submission event.
 */
function handleRegistration(event) {
    event.preventDefault();

    const form = event.target;
    const registerButton = form.querySelector('button');
    const btnText = registerButton.querySelector('.btn-text');
    const btnSpinner = registerButton.querySelector('.btn-spinner');
    const btnIcon = registerButton.querySelector('svg');
    const messageDiv = document.getElementById('registerMessage');

    btnText.style.display = 'none';
    btnIcon.style.display = 'none';
    btnSpinner.style.display = 'flex';
    registerButton.disabled = true;

    const formData = new FormData(form);
    messageDiv.textContent = 'Creating account...';
    messageDiv.style.color = 'black';

    fetch('api/register.php', {
        method: 'POST',
        body: formData
    })
        .then(res => res.json().then(data => ({ ok: res.ok, body: data })))
        .then(({ ok, body }) => {
            messageDiv.textContent = body.message;

            if (ok && body.success) {
                messageDiv.style.color = 'green';
                form.reset();
                if (body.jwt) localStorage.setItem('jwt', body.jwt);
                showSuccess();
            } else messageDiv.style.color = 'red';
        })
        .catch(error => {
            console.error('Register error:', error);
            messageDiv.textContent = 'An unexpected error occurred.';
            messageDiv.style.color = 'red';
        })
        .finally(() => {
            btnText.style.display = '';
            btnIcon.style.display = '';
            btnSpinner.style.display = 'none';
        });
}


document.addEventListener('DOMContentLoaded', function () {
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');
    const authContainer = document.getElementById('authContainer');

    // Attach event listeners for form submissions.
    if (loginForm) loginForm.addEventListener('submit', handleLogin);
    if (registerForm) registerForm.addEventListener('submit', handleRegistration);

    // Initial check for a JWT in local storage. If present, show the success state.
    // Otherwise, remove a CSS class to display the authentication container.
    const jwt = localStorage.getItem('jwt');
    if (jwt) showSuccess(); else authContainer.classList.remove('hidden-until-ready');

    const path = window.location.pathname;

    // Based on the current URL path, remove the 'hidden' class from the
    // appropriate card to display it initially.
    if (path.endsWith('/login')) document.getElementById('loginCard').classList.remove('hidden');
    else if (path.endsWith('/register')) document.getElementById('registerCard').classList.remove('hidden');

    /**
     * Updates the disabled state of a button based on whether all required
     * input fields in its form are filled.
     * @param {HTMLFormElement} form The form containing the inputs.
     * @param {HTMLButtonElement} button The button to update.
     */
    function updateButtonState(form, button) {
        const requiredInputs = form.querySelectorAll('input[required]');
        const allFilled = Array.from(requiredInputs).every(inp => inp.value.trim() !== '');
        button.disabled = !allFilled;
        button.classList.toggle('disabled-btn', !allFilled);
    }

    // Attach an 'input' event listener to each required input in the login form
    // to dynamically enable/disable the login button.
    const loginButton = loginForm.querySelector('button');
    loginForm.querySelectorAll('input[required]').forEach(input =>
        input.addEventListener('input', () => updateButtonState(loginForm, loginButton)));

    // Attach an 'input' event listener to each required input in the registration form
    // to dynamically enable/disable the registration button.
    const registerButton = registerForm.querySelector('button');
    registerForm.querySelectorAll('input[required]').forEach(input =>
        input.addEventListener('input', () => updateButtonState(registerForm, registerButton)));
});