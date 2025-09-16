document.addEventListener('DOMContentLoaded', function () {
    const messages = document.querySelectorAll('.messages');
    messages.forEach(messageContainer => {
        setTimeout(() => {
            messageContainer.style.opacity = '0';
            setTimeout(() => {
                messageContainer.style.display = 'none';
            }, 500);
        }, 5000);
    });
});