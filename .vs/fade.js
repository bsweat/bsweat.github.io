document.addEventListener("DOMContentLoaded", () => {
    document.body.classList.add("fade-in");

    document.querySelectorAll('a').forEach(link => {
        const url = new URL(link.href);
        if (url.origin === window.location.origin) {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const href = link.getAttribute('href');
                document.body.classList.remove('fade-in');
                document.body.style.opacity = '0';
                setTimeout(() => {
                    window.location.href = href;
                }, 600); // Match CSS transition duration
            });
        }
    });
});

s