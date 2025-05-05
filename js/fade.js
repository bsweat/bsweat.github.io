window.addEventListener("DOMContentLoaded", () => {
    document.body.classList.add("fade-in");

    const typingElement = document.querySelector('.typing');
    if (typingElement) {
        const charCount = typingElement.textContent.trim().length;
        typingElement.style.setProperty('--chars', charCount);
    }
});
