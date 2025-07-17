/**
 * Updates the browser's URL path without reloading the page.
 * Uses the History API's pushState method to change the URL.
 *
 * @param {string} path The new URL path to navigate to.
 */
function updateUrl(path) {
    if (window.location.pathname !== path)  window.history.pushState({}, '', path);
}

/**
 * Hides the registration form and displays the login form.
 * It also updates the browser's URL to '/login'.
 */
function showLogin() {
    document.getElementById('loginCard').style.display = 'block';
    document.getElementById('registerCard').style.display = 'none';
    updateUrl('/login');
}

/**
 * Hides the login form and displays the registration form.
 * It also updates the browser's URL to '/register'.
 */
function showRegister() {
    document.getElementById('loginCard').style.display = 'none';
    document.getElementById('registerCard').style.display = 'block';
    updateUrl('/register');
}

/**
 * Hides the loading spinner and the authentication container,
 * and then displays the success message. It also updates the
 * URL to the root path '/'. This function is typically called
 * after a successful login or registration.
 */
function showSuccess() {
    document.getElementById('loadingSpinner').style.display = 'none';
    document.getElementById('authContainer').style.display = 'none';
    document.getElementById('successMessage').style.display = 'block';
    updateUrl('/');
}

/**
 * Hides the loading spinner and makes the authentication container visible
 * by adding the 'show' class.
 */
function showAuthContainer() {
    document.getElementById('loadingSpinner').style.display = 'none';
    document.getElementById('authContainer').classList.add('show');
}

/**
 * Asynchronously checks for a valid session using a JSON Web Token (JWT)
 * stored in local storage.
 *
 * @async
 * @function checkSession
 * @returns {Promise<void>} A promise that resolves when the session check is complete.
 */
async function checkSession() {
    const jwt = localStorage.getItem('jwt');
    if (!jwt) {
        showAuthContainer();
        handleInitialRoute();
        return;
    }
    try {
        const response = await fetch('api/validate_session.php', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${jwt}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ action: 'validate' })
        });
        if (response.ok) {
            const result = await response.json();
            showSuccess();
        } else {
            localStorage.removeItem('jwt');
            showAuthContainer();
            handleInitialRoute();
        }
    } catch (error) {
        console.error('Session check failed:', error);
        showAuthContainer();
        handleInitialRoute();
    }
}

/**
 * Based on the given URL path, this function determines which
 * authentication card (login or register) to display.
 *
 * @param {string} path The URL pathname from `window.location.pathname`.
 */
function handleRouting(path) {
    if (path === '/register') {
        document.getElementById('registerCard').style.display = 'block';
        document.getElementById('loginCard').style.display = 'none';
    } else {
        document.getElementById('loginCard').style.display = 'block';
        document.getElementById('registerCard').style.display = 'none';
    }
}

/**
 * Handles the initial page load by checking the current URL path
 * and calling `handleRouting` to display the appropriate card.
 */
function handleInitialRoute() {
    const path = window.location.pathname;
    handleRouting(path);
}

document.addEventListener('DOMContentLoaded', function() {
    // Check for an existing session upon page load.
    checkSession().then();

    // Event listener for the 'registerLink' to switch to the registration form.
    document.getElementById('registerLink').addEventListener('click', function(event) {
        event.preventDefault();
        showRegister();
    });

    // Event listener for the 'loginLink' to switch to the login form.
    document.getElementById('loginLink').addEventListener('click', function(event) {
        event.preventDefault();
        showLogin();
    });

    // Event listener for the browser's back/forward buttons (popstate)
    // to handle navigation and display the correct card.
    window.addEventListener('popstate', function() {handleRouting(window.location.pathname)});
});